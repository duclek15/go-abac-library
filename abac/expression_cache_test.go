// file: go-abac-library/abac/expression_cache_test.go
package abac_test

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/duclek15/go-abac-library/abac"
)

// ===== Corpus: tải + lọc =====

type corpusRule struct {
	Tenant string
	Rule   string
	Effect string
}

// loadCorpusRules đọc testdata/rules_corpus.txt — xem header file đó để biết
// nguồn gốc (rule THẬT từ casbin_rule DB dev + rule tự soạn bổ sung cú
// pháp). Dòng REAL có thêm cột thứ 4 "# [REAL #<id>]" (comment truy vết) —
// bị bỏ qua, không phải một phần rule.
func loadCorpusRules(t testing.TB) []corpusRule {
	t.Helper()
	data, err := os.ReadFile("testdata/rules_corpus.txt")
	if err != nil {
		t.Fatalf("đọc corpus: %v", err)
	}
	var rules []corpusRule
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) < 3 {
			t.Fatalf("dòng corpus %d sai định dạng (cần tenant<TAB>rule<TAB>effect): %q", lineNo+1, line)
		}
		rules = append(rules, corpusRule{
			Tenant: parts[0],
			Rule:   parts[1],
			Effect: strings.TrimSpace(parts[2]),
		})
	}
	if len(rules) == 0 {
		t.Fatalf("corpus rỗng")
	}
	return rules
}

// funcCallPattern bắt tên định danh đứng ngay trước dấu '(' — dùng để dò các
// hàm mà một rule gọi tới.
var funcCallPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// stringLiteralPattern khớp một chuỗi literal của govaluate ('...' hoặc
// "..."), dùng để CẮT BỎ trước khi dò lời gọi hàm — nếu không, một pattern
// regex bên trong matches(Action, "...auto_schedule_(run|read|...)") sẽ bị
// funcCallPattern nhận nhầm thành lời gọi hàm "auto_schedule_(...)" (đã xảy
// ra thật khi chạy lần đầu, xem báo cáo thi công).
var stringLiteralPattern = regexp.MustCompile(`'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`)

// filterExecutable giữ lại rule mà MỌI hàm nó gọi đều có trong `registered`.
// Rule gọi hàm lạ bị loại (đếm theo tên hàm) — đây là cơ chế "loại khỏi
// corpus có lý do" mà phase yêu cầu, thay vì viết stub giả cho hàm không có.
func filterExecutable(rules []corpusRule, registered abac.CustomFunctionMap) (usable []corpusRule, excludedFuncs map[string]int) {
	excludedFuncs = make(map[string]int)
	for _, r := range rules {
		ok := true
		withoutLiterals := stringLiteralPattern.ReplaceAllString(r.Rule, "")
		for _, m := range funcCallPattern.FindAllStringSubmatch(withoutLiterals, -1) {
			name := m[1]
			if _, known := registered[name]; !known {
				ok = false
				excludedFuncs[name]++
			}
		}
		if ok {
			usable = append(usable, r)
		}
	}
	return usable, excludedFuncs
}

// TestFilterExecutable_ExcludesUnknownFunctions kiểm trực tiếp cơ chế lọc —
// độc lập với nội dung corpus thật (vốn hiện không có rule nào bị loại vì
// backendRealFunctions() đã phủ đủ 6 hàm mà 22 rule thật cần). Không test
// này thì cơ chế "loại rule gọi hàm chưa đăng ký" chỉ tồn tại trên giấy,
// chưa từng được thấy chạy.
func TestFilterExecutable_ExcludesUnknownFunctions(t *testing.T) {
	registered := abac.CustomFunctionMap{"has": abac.HasFunc}
	rules := []corpusRule{
		{Tenant: "*", Rule: "has(Subject.tags, 'x')", Effect: "allow"},
		{Tenant: "*", Rule: "customPredicateNotRegistered(Subject, 'y')", Effect: "allow"},
		{Tenant: "*", Rule: "has(Subject.tags, 'x') && anotherMissingFunc(Resource)", Effect: "deny"},
	}
	usable, excluded := filterExecutable(rules, registered)
	if len(usable) != 1 || usable[0].Rule != rules[0].Rule {
		t.Fatalf("usable = %+v, muốn đúng 1 rule (rules[0])", usable)
	}
	if excluded["customPredicateNotRegistered"] != 1 {
		t.Fatalf("excluded['customPredicateNotRegistered'] = %d, muốn 1", excluded["customPredicateNotRegistered"])
	}
	if excluded["anotherMissingFunc"] != 1 {
		t.Fatalf("excluded['anotherMissingFunc'] = %d, muốn 1", excluded["anotherMissingFunc"])
	}
}

// corpusFunctions gộp 7 hàm built-in CÓ THẬT của go-abac-library với 6 hàm
// predicate thật copy từ backend (corpus_functions_test.go) — đúng bằng tập
// hàm mà mọi rule (REAL + SELF-AUTHORED) trong testdata/rules_corpus.txt gọi
// tới. "matches" dùng bản copy từ backend (có cache + giới hạn độ dài, sát
// với chi phí predicate thật hơn bản built-in của thư viện).
func corpusFunctions() abac.CustomFunctionMap {
	fns := abac.CustomFunctionMap{
		"has":             abac.HasFunc,
		"intersects":      abac.IntersectsFunc,
		"isIpInCidr":      abac.IsIpInCidrFunc,
		"isBusinessHours": abac.IsBusinessHoursFunc,
		"hasGlobalRole":   abac.HasGlobalRoleFunc,
		"hasTenantRole":   abac.HasTenantRoleFunc,
		"hasOrgRole":      abac.HasOrgRoleFunc,
	}
	for name, fn := range backendRealFunctions() {
		fns[name] = fn
	}
	return fns
}

// ===== Fixtures: subject/resource/env dùng chung cho differential + benchmark =====

// Mọi fixture Subject/Resource dưới đây đều khai đủ MỌI key mà accessor
// trong corpus có thể đụng tới (id, role, tags, department, owner,
// organizations, global_roles, tenants) dù giá trị rỗng — govaluate báo LỖI
// (không phải false) khi truy cập key không tồn tại trên map, và một hàng
// policy lỗi làm Enforce() dừng đánh giá các hàng còn lại. Thiếu key ở đây
// từng khiến hầu hết rule phía sau trong corpus (~40/42) không bao giờ được
// evaluate tới — differential/benchmark tưởng chạy qua cả corpus nhưng thật
// ra chỉ chạm rule đầu tiên (xem báo cáo thi công).
//
// "tags" cố ý dùng []string (không phải []interface{}): govaluate v1.8.0 có
// một quirk thật ở separatorStage (evaluationStage.go) — khi arg0 của một
// lời gọi hàm tự nó có kiểu ĐỘNG là []interface{}, separatorStage coi nó là
// danh sách tham số ĐÃ TÍCH LUỸ (append(left, right)) thay vì một giá trị
// slice đơn — has(Subject.tags, 'vip') với Subject.tags kiểu []interface{}
// bị "xoè" thành has("vip", "vip") thay vì has([]interface{}{"vip"}, "vip").
// Dùng []string né được quirk này vì type switch không khớp case
// []interface{} — không phải cách né tình cờ, đã xác minh bằng probe test
// trực tiếp trên govaluate (xem báo cáo thi công), không phải bug trong cache
// của phase này (xảy ra giống hệt ở cả đường cached lẫn uncached).
var corpusSubjects = map[string]abac.Attributes{
	"sudo_user": {
		"id":            "sudo_user",
		"role":          "sudo",
		"tags":          []string{},
		"global_roles":  []interface{}{},
		"tenants":       []interface{}{},
		"organizations": []interface{}{},
	},
	"root_user": {
		"id":           "root_user",
		"role":         "",
		"tags":         []string{"vip"},
		"global_roles": []interface{}{"root"},
		"tenants": []interface{}{
			map[string]interface{}{
				"id":   "tenant1",
				"role": "hr_manager",
				"organizations": []interface{}{
					map[string]interface{}{"id": "org1", "role": "manager"},
				},
			},
		},
		"organizations": []interface{}{},
	},
	"org1_admin": {
		"id":           "org1_admin",
		"role":         "",
		"tags":         []string{},
		"global_roles": []interface{}{},
		"tenants":      []interface{}{},
		"organizations": []interface{}{
			map[string]interface{}{
				"id":             "org1",
				"role":           "admin",
				"assigned_roles": []interface{}{"admin", "academic_manager"},
			},
		},
	},
	"org1_teacher": {
		"id":           "org1_teacher",
		"role":         "",
		"tags":         []string{},
		"global_roles": []interface{}{},
		"tenants":      []interface{}{},
		"organizations": []interface{}{
			map[string]interface{}{
				"id":             "org1",
				"role":           "teacher",
				"assigned_roles": []interface{}{"teacher"},
			},
		},
	},
	"org1_student": {
		"id":           "org1_student",
		"role":         "student",
		"tags":         []string{"banned"},
		"global_roles": []interface{}{},
		"tenants":      []interface{}{},
		"organizations": []interface{}{
			map[string]interface{}{"id": "org1", "role": "student"},
		},
	},
	"guest_user": {
		"id":            "guest_user",
		"role":          "guest",
		"tags":          []string{},
		"global_roles":  []interface{}{},
		"tenants":       []interface{}{},
		"organizations": []interface{}{},
	},
}

var corpusResources = map[string]abac.Attributes{
	"res_org1": {
		"id":         "res_org1",
		"department": "hr",
		"tags":       []string{"vip"},
		"owner":      "user_42",
		"organizations": []interface{}{
			map[string]interface{}{"id": "org1"},
		},
	},
	"res_org2": {
		"id":         "res_org2",
		"department": "finance",
		"tags":       []string{"restricted"},
		"owner":      "user_7",
		"organizations": []interface{}{
			map[string]interface{}{"id": "org2"},
		},
	},
	"res_payroll": {
		"id":         "res_payroll",
		"department": "payroll",
		"tags":       []string{},
		"owner":      "nobody",
		"organizations": []interface{}{
			map[string]interface{}{"id": "org1"},
		},
	},
}

func corpusEnv(hour float64, channel, ip string) abac.Attributes {
	return abac.Attributes{"hour": hour, "channel": channel, "ip": ip}
}

var (
	envBusinessMobile = corpusEnv(10, "mobile", "10.1.2.3")
	envLateNightWeb   = corpusEnv(23, "web", "8.8.8.8")
	envEarlyMorning   = corpusEnv(3, "desktop", "10.5.5.5")
)

type corpusFetcher struct{}

func (corpusFetcher) GetSubjectAttributes(_ *context.Context, subject interface{}) (abac.Attributes, error) {
	id, _ := subject.(string)
	if attrs, ok := corpusSubjects[id]; ok {
		return attrs, nil
	}
	return nil, abac.ErrSubjectNotFound
}

func (corpusFetcher) GetResourceAttributes(_ *context.Context, resource interface{}) ([]abac.Attributes, error) {
	id, _ := resource.(string)
	if attrs, ok := corpusResources[id]; ok {
		return []abac.Attributes{attrs}, nil
	}
	return nil, abac.ErrResourceNotFound
}

// buildCorpusAuthorizer ghi `rules` ra một file policy CSV tạm (dùng
// encoding/csv để quote đúng chuẩn — rule text chứa dấu phẩy ở khắp nơi,
// NewABACSystemFromStrings tách bằng strings.Split thô nên KHÔNG dùng được
// cho corpus này) rồi nạp qua NewABACSystemFromFile.
func buildCorpusAuthorizer(t testing.TB, rules []corpusRule, opts ...abac.AuthorizerOption) *abac.Authorizer {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.csv")
	f, err := os.Create(policyPath)
	if err != nil {
		t.Fatalf("tạo file policy tạm: %v", err)
	}
	w := csv.NewWriter(f)
	for _, r := range rules {
		if err := w.Write([]string{"p", r.Tenant, r.Rule, r.Effect}); err != nil {
			t.Fatalf("ghi policy csv: %v", err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		t.Fatalf("flush policy csv: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("đóng file policy: %v", err)
	}

	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf", policyPath, corpusFetcher{}, corpusFetcher{}, corpusFunctions(), opts...,
	)
	if err != nil {
		t.Fatalf("tạo authorizer từ corpus: %v", err)
	}
	return authorizer
}

// ===== Scenario dùng cho differential test + benchmark =====

type corpusScenario struct {
	name     string
	tenantID string
	subject  string
	resource string
	action   string
	env      abac.Attributes
}

var corpusScenarios = []corpusScenario{
	{"root sudo mọi quyền, tenant1, approve", "tenant1", "root_user", "res_org1", "approve_level_2", envBusinessMobile},
	{"sudo_user qua Subject.role trực tiếp", "*", "sudo_user", "res_org1", "tenant:list", envBusinessMobile},
	{"org1_admin exam_schedule list", "*", "org1_admin", "res_org1", "exam_schedule:list", envBusinessMobile},
	{"org1_teacher exam_schedule delete", "*", "org1_teacher", "res_org1", "exam_schedule:delete", envBusinessMobile},
	{"org1_student bị deny theo rule hasAnyOrgRole student", "*", "org1_student", "res_org1", "exam_schedule:read", envLateNightWeb},
	{"guest_user view_directory, ngoài giờ hành chính", "*", "guest_user", "res_payroll", "view_directory", envEarlyMorning},
	{"root_user checkin trong giờ hành chính", "*", "root_user", "res_org1", "checkin", envBusinessMobile},
	{"root_user checkin ngoài giờ hành chính", "*", "root_user", "res_org1", "checkin", envLateNightWeb},
	{"hr_manager tenant2 duyệt hr", "tenant2", "root_user", "res_org1", "approve_level_2", envBusinessMobile},
	{"tenant thật từ DB dev (UUID)", "3414821b-e57f-4e4f-82fc-3d52fa8d54e6", "org1_admin", "res_org1", "student:list", envBusinessMobile},
	{"admin_panel trong dải CIDR", "*", "org1_admin", "res_org1", "admin_panel", envBusinessMobile},
	{"admin_panel ngoài dải CIDR", "*", "org1_admin", "res_org2", "admin_panel", envLateNightWeb},
	{"subject không tồn tại -> lỗi", "*", "unknown_subject", "res_org1", "approve_level_2", envBusinessMobile},
}

// sortedAttributesEvaluated trả bản sao đã sắp xếp của AttributesEvaluated.
// Thứ tự phần tử ở đây đến từ `for k, v := range subAttrs` (subAttrs là
// map[string]interface{}) trong Check/CheckWithTrace — Go CỐ Ý random hoá
// thứ tự duyệt map ở mỗi lần chạy, kể cả trên cùng một Authorizer không hề
// đụng tới cache. Đây là non-determinism có sẵn từ TRƯỚC cache (không phải
// do phase này gây ra) nên differential không so thứ tự chỗ này — chỉ so
// ĐÚNG TẬP phần tử. Predicates và MatchedPolicies thì KHÔNG sort — thứ tự ở
// đó phản ánh thứ tự đánh giá thật (functions gọi tuần tự trong expression,
// policy duyệt tuần tự theo GetPolicy()) và chính là bất biến mà cache phải
// giữ nguyên.
func sortedAttributesEvaluated(items []abac.AttributeAccess) []abac.AttributeAccess {
	out := make([]abac.AttributeAccess, len(items))
	copy(out, items)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].ValuePreview < out[j].ValuePreview
	})
	return out
}

func assertTraceEqual(t *testing.T, name string, a, b *abac.DecisionTrace) {
	t.Helper()
	if a == nil || b == nil {
		if a != b {
			t.Fatalf("%s: một trace nil, trace kia không (cached=%v, uncached=%v)", name, a, b)
		}
		return
	}
	na, nb := *a, *b
	// Thời gian chạy không phải bất biến cần so — differential chỉ quan tâm
	// nội dung quyết định, không quan tâm mất bao lâu để ra quyết định đó.
	na.EvaluationMs, nb.EvaluationMs = 0, 0
	na.AttributesEvaluated = sortedAttributesEvaluated(na.AttributesEvaluated)
	nb.AttributesEvaluated = sortedAttributesEvaluated(nb.AttributesEvaluated)
	if !reflect.DeepEqual(na, nb) {
		t.Fatalf("%s: trace khác nhau giữa cached và uncached:\n cached:   %+v\n uncached: %+v", name, na, nb)
	}
}

// TestExpressionCache_DifferentialCachedVsUncached là bài test cốt lõi của
// phase: dựng hai Authorizer từ ĐÚNG MỘT nội dung policy — một bật cache mặc
// định, một tắt qua WithoutExpressionCache() (đường evaluateUncached, giữ
// nguyên logic gốc trước khi có cache, dùng làm oracle) — rồi so (result,
// err) LẪN toàn bộ nội dung trace cho từng scenario. Chạy 2 vòng: vòng đầu
// buộc cache populate lần đầu (song song với oracle), vòng hai buộc cache TÁI
// SỬ DỤNG expression đã parse — differential vẫn phải đúng ở cả hai vòng.
func TestExpressionCache_DifferentialCachedVsUncached(t *testing.T) {
	all := loadCorpusRules(t)
	usable, excluded := filterExecutable(all, corpusFunctions())
	if len(usable) == 0 {
		t.Fatalf("không có rule nào chạy được sau khi lọc — kiểm tra lại corpusFunctions()")
	}
	if len(excluded) > 0 {
		t.Logf("corpus có %d/%d rule bị loại (gọi hàm chưa đăng ký, không viết stub giả): %v",
			len(all)-len(usable), len(all), excluded)
	} else {
		t.Logf("dùng %d/%d rule của corpus (không rule nào bị loại — backendRealFunctions() đã phủ đủ)", len(usable), len(all))
	}

	cachedAuth := buildCorpusAuthorizer(t, usable)
	uncachedAuth := buildCorpusAuthorizer(t, usable, abac.WithoutExpressionCache())

	traceOpts := []abac.TraceOption{abac.WithPredicateTracing(true), abac.WithAttributeTracing(true)}

	runOnce := func(t *testing.T, round string) {
		for _, sc := range corpusScenarios {
			t.Run(sc.name, func(t *testing.T) {
				ctx := context.Background()
				env := sc.env
				allowedC, traceC, errC := cachedAuth.CheckWithTrace(&ctx, sc.tenantID, sc.subject, sc.resource, sc.action, &env, traceOpts...)
				allowedU, traceU, errU := uncachedAuth.CheckWithTrace(&ctx, sc.tenantID, sc.subject, sc.resource, sc.action, &env, traceOpts...)

				if (errC == nil) != (errU == nil) {
					t.Fatalf("%s: khác biệt về có lỗi hay không: cached err=%v, uncached err=%v", round, errC, errU)
				}
				if errC != nil && errC.Error() != errU.Error() {
					t.Fatalf("%s: nội dung lỗi khác nhau:\n cached:   %v\n uncached: %v", round, errC, errU)
				}
				if allowedC != allowedU {
					t.Fatalf("%s: kết quả allow khác nhau: cached=%v, uncached=%v", round, allowedC, allowedU)
				}
				assertTraceEqual(t, round+"/"+sc.name, traceC, traceU)
			})
		}
	}

	t.Run("vòng 1 (cache nguội)", func(t *testing.T) { runOnce(t, "vòng1") })
	t.Run("vòng 2 (cache đã ấm, expression tái sử dụng)", func(t *testing.T) { runOnce(t, "vòng2") })
}

// TestExpressionCache_WithoutExpressionCache_StillCorrect: kill-switch không
// được phép đổi kết quả phân quyền — chỉ đổi có cache hay không (khẳng định
// cache==nil ở test nội bộ expression_cache_internal_test.go).
func TestExpressionCache_WithoutExpressionCache_StillCorrect(t *testing.T) {
	rules := []corpusRule{{Tenant: "*", Rule: `Subject.role == "sudo"`, Effect: "allow"}}
	authorizer := buildCorpusAuthorizer(t, rules, abac.WithoutExpressionCache())
	ctx := context.Background()
	allowed, err := authorizer.Check(&ctx, "*", "sudo_user", "res_org1", "any_action", nil)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Fatalf("mong đợi allow=true cho sudo_user với WithoutExpressionCache()")
	}
}

// ===== Race: cô lập trace giữa các request đồng thời =====

// raceIsolationFetcher trả attrs mà Subject.id CHÍNH LÀ subject truyền vào —
// mỗi goroutine/iteration dùng một subject ID riêng để dò rò rỉ trực tiếp
// qua nội dung Arguments của predicate trong DecisionTrace công khai, không
// cần inject TraceObserver tuỳ biến (API công khai không cho phép việc đó).
type raceIsolationFetcher struct{}

func (raceIsolationFetcher) GetSubjectAttributes(_ *context.Context, subject interface{}) (abac.Attributes, error) {
	id, _ := subject.(string)
	return abac.Attributes{"id": id, "global_roles": []interface{}{"root"}}, nil
}

func (raceIsolationFetcher) GetResourceAttributes(_ *context.Context, _ interface{}) ([]abac.Attributes, error) {
	return nil, nil
}

// TestExpressionCache_TraceIsolationUnderConcurrency là race test yêu cầu
// của phase: nhiều goroutine cùng CheckWithTrace trên CÙNG MỘT ruleStr (nên
// cùng chia sẻ một *rulePool trong cache), mỗi goroutine dùng subject ID
// RIÊNG (nhúng thẳng vào Subject truyền cho hasGlobalRole) — nếu trace rò rỉ
// giữa request, hoặc arg0 của predicate ghi nhận được sẽ KHÔNG chứa đúng
// subjectID của goroutine đang hỏi (predicate đó đã "chạy hộ" observer của
// goroutine khác), hoặc trace sẽ có 0 predicate (bị "cướp" bởi goroutine
// khác). Trên code TRƯỚC khi có cache / SAU khi có pool: phải xanh. Với một
// cache ngây thơ (map ruleStr -> *EvaluableExpression, wrap hàm MỘT LẦN lúc
// tạo, capture req.Trace của lần tạo đó): phải ĐỎ — xem báo cáo thi công để
// đọc output go test -race thực tế của bước chứng minh này.
func TestExpressionCache_TraceIsolationUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.csv")
	content := "p,*,\"hasGlobalRole(Subject, 'root')\",allow\n"
	if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
		t.Fatalf("ghi policy: %v", err)
	}

	fns := abac.CustomFunctionMap{"hasGlobalRole": abac.HasGlobalRoleFunc}
	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf", policyPath, raceIsolationFetcher{}, raceIsolationFetcher{}, fns,
	)
	if err != nil {
		t.Fatalf("tạo authorizer: %v", err)
	}

	const goroutines = 40
	const itersPerGoroutine = 60

	var wg sync.WaitGroup
	failed := make(chan string, goroutines*itersPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < itersPerGoroutine; i++ {
				subjectID := fmt.Sprintf("subj-%d-%d", g, i)
				_, trace, err := authorizer.CheckWithTrace(&ctx, "*", subjectID, "any_resource", "any_action", nil,
					abac.WithPredicateTracing(true))
				if err != nil {
					failed <- fmt.Sprintf("goroutine %d iter %d: lỗi %v", g, i, err)
					continue
				}
				if len(trace.Predicates) != 1 {
					failed <- fmt.Sprintf("goroutine %d iter %d (subject=%s): trace có %d predicate, muốn đúng 1", g, i, subjectID, len(trace.Predicates))
					continue
				}
				gotArg := trace.Predicates[0].Arguments["arg0"]
				if !strings.Contains(gotArg, subjectID) {
					failed <- fmt.Sprintf("goroutine %d iter %d: predicate arg0=%q không chứa subjectID riêng %q — trace đã nhận predicate của goroutine/lần gọi khác", g, i, gotArg, subjectID)
				}
			}
		}(g)
	}
	wg.Wait()
	close(failed)

	var msgs []string
	for m := range failed {
		msgs = append(msgs, m)
	}
	if len(msgs) > 0 {
		limit := len(msgs)
		if limit > 20 {
			limit = 20
		}
		t.Fatalf("rò rỉ trace giữa request (%d lỗi trên tổng %d lần gọi, in %d đầu tiên):\n%s",
			len(msgs), goroutines*itersPerGoroutine, limit, strings.Join(msgs[:limit], "\n"))
	}
}

// ===== Benchmark: đo bằng predicate THẬT (backendRealFunctions), trên toàn
// bộ corpus đã lọc (Enforce() đánh giá tất cả policy đang active mỗi lần) =====

func benchmarkCorpusAuthorizer(b *testing.B, opts ...abac.AuthorizerOption) *abac.Authorizer {
	b.Helper()
	all := loadCorpusRules(b)
	usable, _ := filterExecutable(all, corpusFunctions())
	return buildCorpusAuthorizer(b, usable, opts...)
}

func BenchmarkAuthorizerCheck_NoCache(b *testing.B) {
	authorizer := benchmarkCorpusAuthorizer(b, abac.WithoutExpressionCache())
	ctx := context.Background()
	sc := corpusScenarios[0]
	env := sc.env
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := authorizer.Check(&ctx, sc.tenantID, sc.subject, sc.resource, sc.action, &env); err != nil {
			b.Fatalf("Check: %v", err)
		}
	}
}

func BenchmarkAuthorizerCheck_WithCache(b *testing.B) {
	authorizer := benchmarkCorpusAuthorizer(b)
	ctx := context.Background()
	sc := corpusScenarios[0]
	env := sc.env
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := authorizer.Check(&ctx, sc.tenantID, sc.subject, sc.resource, sc.action, &env); err != nil {
			b.Fatalf("Check: %v", err)
		}
	}
}

func BenchmarkAuthorizerCheckWithTrace_NoCache(b *testing.B) {
	authorizer := benchmarkCorpusAuthorizer(b, abac.WithoutExpressionCache())
	ctx := context.Background()
	sc := corpusScenarios[0]
	env := sc.env
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := authorizer.CheckWithTrace(&ctx, sc.tenantID, sc.subject, sc.resource, sc.action, &env,
			abac.WithPredicateTracing(true), abac.WithAttributeTracing(true)); err != nil {
			b.Fatalf("CheckWithTrace: %v", err)
		}
	}
}

func BenchmarkAuthorizerCheckWithTrace_WithCache(b *testing.B) {
	authorizer := benchmarkCorpusAuthorizer(b)
	ctx := context.Background()
	sc := corpusScenarios[0]
	env := sc.env
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := authorizer.CheckWithTrace(&ctx, sc.tenantID, sc.subject, sc.resource, sc.action, &env,
			abac.WithPredicateTracing(true), abac.WithAttributeTracing(true)); err != nil {
			b.Fatalf("CheckWithTrace: %v", err)
		}
	}
}
