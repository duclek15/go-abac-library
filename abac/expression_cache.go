// file: go-abac-library/abac/expression_cache.go
package abac

import (
	"fmt"
	"sync"

	"github.com/casbin/govaluate"
)

// pooledExpr đóng gói một *govaluate.EvaluableExpression đã parse cùng một
// "slot" observer ổn định. Các hàm tùy chỉnh được wrap MỘT LẦN lúc parse (xem
// newPooledExpr) để đọc `obs` tại THỜI ĐIỂM CHẠY qua con trỏ tới chính
// pooledExpr này — KHÔNG capture request nào. Nhờ vậy, dù expr được tái sử
// dụng giữa nhiều request khác nhau (đó là mục đích của cache), predicate vẫn
// luôn báo cáo về đúng observer của request đang cầm item này tại thời điểm
// Evaluate chạy, không phải observer của request đã tạo ra expr lúc đầu.
//
// Isolation không tới từ khóa (lock) mà tới từ SỞ HỮU ĐỘC QUYỀN: mỗi lần
// rulePool.get() trả về một pooledExpr, chỉ goroutine gọi nó được đụng vào
// item đó cho tới khi put() lại — sync.Pool đảm bảo hai goroutine không bao
// giờ cùng cầm chung một pooledExpr.
type pooledExpr struct {
	expr *govaluate.EvaluableExpression
	obs  TraceObserver // nil khi request hiện tại không bật predicate tracing
}

// newPooledExpr parse ruleStr một lần, wrap userFunctions để mỗi lần hàm được
// gọi sẽ đọc obs của CHÍNH item này (không phải của request nào tại thời điểm
// parse). Trả lỗi parse nguyên văn — lỗi này KHÔNG được cache (xem rulePool).
func newPooledExpr(ruleStr string, userFunctions CustomFunctionMap) (*pooledExpr, error) {
	item := &pooledExpr{}

	wrapped := make(CustomFunctionMap, len(userFunctions))
	for name, fn := range userFunctions {
		n := name
		orig := fn
		wrapped[n] = func(fnArgs ...interface{}) (interface{}, error) {
			res, err := orig(fnArgs...)
			if item.obs != nil {
				boolRes := false
				if b, ok := res.(bool); ok {
					boolRes = b
				}
				item.obs.OnPredicate(n, fnArgs, boolRes)
			}
			return res, err
		}
	}

	expr, err := govaluate.NewEvaluableExpressionWithFunctions(ruleStr, wrapped)
	if err != nil {
		return nil, err
	}
	item.expr = expr
	return item, nil
}

// rulePool giữ các bản sao *pooledExpr đã parse sẵn cho MỘT ruleStr cụ thể.
// Dùng sync.Pool: Get() trả về một bản độc quyền cho goroutine gọi (parse mới
// nếu pool rỗng), Put() trả lại sau khi dùng xong.
type rulePool struct {
	pool sync.Pool
}

// newRulePool parse thử ruleStr một lần để phát hiện lỗi cú pháp ngay tại đây
// (không đưa entry lỗi vào cache — xem expressionCache.getPool). Các lần New
// tiếp theo (khi pool rỗng, sync.Pool cần thêm bản sao) parse lại cùng
// ruleStr; vì input không đổi, việc parse lại không thể lỗi khác lần đầu.
func newRulePool(ruleStr string, userFunctions CustomFunctionMap) (*rulePool, error) {
	first, err := newPooledExpr(ruleStr, userFunctions)
	if err != nil {
		return nil, err
	}
	rp := &rulePool{}
	rp.pool.New = func() interface{} {
		item, err := newPooledExpr(ruleStr, userFunctions)
		if err != nil {
			// Không thể xảy ra trong vận hành bình thường: ruleStr đã parse
			// thành công ở newRulePool và không đổi. Trả nil để get() tự phát
			// hiện và rơi về đường không cache thay vì panic.
			return nil
		}
		return item
	}
	rp.pool.Put(first)
	return rp, nil
}

// get lấy một pooledExpr độc quyền cho goroutine gọi. Trả nil nếu New() gặp
// lỗi bất thường (xem newRulePool) — caller phải tự fallback, không được coi
// nil là hợp lệ.
func (rp *rulePool) get() *pooledExpr {
	v := rp.pool.Get()
	if v == nil {
		return nil
	}
	item, ok := v.(*pooledExpr)
	if !ok {
		return nil
	}
	return item
}

// put trả item về pool sau khi dùng xong, xoá obs trước khi trả để không giữ
// tham chiếu treo tới observer của request vừa xong (dọn rác sớm, tránh giữ
// sống trace của request cũ lâu hơn cần thiết dù không ảnh hưởng đúng đắn).
func (rp *rulePool) put(item *pooledExpr) {
	item.obs = nil
	rp.pool.Put(item)
}

// expressionCache ánh xạ ruleStr -> *rulePool. Dùng sync.Map vì đọc nhiều
// (mỗi lần Evaluate) ghi ít (chỉ khi gặp ruleStr mới hoặc khi eviction chạy).
//
// Cross-tenant: Authorizer là singleton dùng chung toàn platform, nên map này
// KHÔNG được phép phình vô hạn khi org-admin sửa/xoá policy (mỗi lần sửa sinh
// ruleStr mới, key cũ mồ côi). Xem PolicyManager.syncExpressionCache — sau mỗi
// lần enforcer đổi policy, evictExcept() dọn hết entry không còn nằm trong tập
// rule đang active.
type expressionCache struct {
	entries       sync.Map // ruleStr string -> *rulePool
	userFunctions CustomFunctionMap
}

func newExpressionCache(userFunctions CustomFunctionMap) *expressionCache {
	return &expressionCache{userFunctions: userFunctions}
}

// getPool trả về *rulePool cho ruleStr, tạo mới (parse) nếu chưa có trong
// cache. Lỗi parse KHÔNG được lưu vào map — rule hỏng phải báo lỗi ở MỌI lần
// gọi, không được "cache" thành công một lần rồi im lặng những lần sau (hay
// ngược lại, không được nhớ lỗi khiến rule sau khi sửa đúng vẫn báo lỗi cũ).
//
// Hai goroutine cùng lần đầu gặp một ruleStr mới có thể cùng parse (lãng phí
// nhỏ, không sai) — LoadOrStore chọn ra một bản làm chính thức, bản còn lại bị
// bỏ cho GC dọn. Đánh đổi này chọn KISS thay vì thêm singleflight/mutex cho
// một tình huống chỉ xảy ra ở lần đầu mỗi ruleStr.
func (c *expressionCache) getPool(ruleStr string) (*rulePool, error) {
	if v, ok := c.entries.Load(ruleStr); ok {
		return v.(*rulePool), nil
	}
	rp, err := newRulePool(ruleStr, c.userFunctions)
	if err != nil {
		return nil, err
	}
	actual, _ := c.entries.LoadOrStore(ruleStr, rp)
	return actual.(*rulePool), nil
}

// evictExcept xoá mọi entry mà ruleStr không có mặt trong `active`. Trả về số
// entry đã xoá — dùng cho test khẳng định eviction thực sự chạy.
func (c *expressionCache) evictExcept(active map[string]struct{}) int {
	evicted := 0
	c.entries.Range(func(key, _ interface{}) bool {
		k := key.(string)
		if _, ok := active[k]; !ok {
			c.entries.Delete(k)
			evicted++
		}
		return true
	})
	return evicted
}

// len đếm số entry hiện có trong cache — dùng cho test.
func (c *expressionCache) len() int {
	n := 0
	c.entries.Range(func(_, _ interface{}) bool {
		n++
		return true
	})
	return n
}

// evaluateCached là đường đánh giá CÓ cache: lấy (hoặc parse-và-lưu) rulePool
// cho ruleStr, mượn một pooledExpr độc quyền, gán observer của request hiện
// tại (nil nếu request này không bật predicate tracing) rồi chạy. Vì mỗi
// goroutine cầm một pooledExpr riêng trong suốt thời gian Evaluate, không có
// hai request nào có thể nhìn thấy observer của nhau dù dùng chung expression
// đã parse.
func (ev *expressionEvaluator) evaluateCached(ruleStr string, req *AuthorizationRequest, policyID, ruleID string) (interface{}, error) {
	pool, err := ev.cache.getPool(ruleStr)
	if err != nil {
		return false, fmt.Errorf("invalid rule syntax '%s': %w", ruleStr, err)
	}

	item := pool.get()
	if item == nil {
		// New() của sync.Pool gặp lỗi bất thường (không thể xảy ra — xem
		// newRulePool) — fallback an toàn về đường parse-mỗi-lần thay vì panic
		// hoặc trả sai kết quả phân quyền.
		return ev.evaluateUncached(ruleStr, req, policyID, ruleID)
	}
	defer pool.put(item)

	if req != nil && req.Trace != nil && req.TraceCfg != nil && req.TraceCfg.enablePredicateTracing {
		item.obs = req.Trace
	}

	return evaluateParsedExpr(item.expr, req, ruleStr, policyID, ruleID)
}
