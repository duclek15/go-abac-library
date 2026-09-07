// file: go-abac-library/abac/authorizer.go
package abac

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/casbin/govaluate"
	"gorm.io/gorm"
	"strings"
	"time"
)

// Authorizer là PDP, chứa logic phân quyền.
//
// enforcer dùng *casbin.SyncedEnforcer (không phải *casbin.Enforcer trần) vì
// nó là singleton dùng chung cho cả process: mọi request PEP gọi Enforce()
// đồng thời với LoadPolicy() chạy nền (reconciler định kỳ + xử lý sự kiện đổi
// policy). SyncedEnforcer tự bọc RWMutex quanh mọi entrypoint (Enforce, AddPolicy,
// LoadPolicy, ...) nên không có đường nào lọt lưới như khi tự khoá thủ công.
type Authorizer struct {
	enforcer        *casbin.SyncedEnforcer
	subjectFetcher  SubjectFetcher
	resourceFetcher ResourceFetcher

	// cache là expression cache dùng chung với expressionEvaluator (qua closure
	// AddFunction bên dưới). Enforce/Check không cần trực tiếp đọc field này —
	// nó chỉ được giữ lại để test nội bộ (package abac) soi kích thước cache;
	// nil nếu tạo Authorizer với WithoutExpressionCache().
	cache *expressionCache
}

type CustomFunctionMap map[string]govaluate.ExpressionFunction

// expressionEvaluator là một struct giữ trạng thái các hàm tùy chỉnh của người dùng.
type expressionEvaluator struct {
	userFunctions CustomFunctionMap

	// cache giữ pool các expression govaluate đã parse, theo khóa là văn bản
	// rule (xem expression_cache.go). nil khi bị tắt qua WithoutExpressionCache()
	// — khi đó Evaluate luôn đi đường parse-mỗi-lần (evaluateUncached).
	cache *expressionCache
}

// authorizerConfig gom các tuỳ chọn tạo Authorizer (hiện chỉ có kill-switch
// cache). Thêm field mới ở đây, không đổi chữ ký constructor.
type authorizerConfig struct {
	disableExpressionCache bool
}

// AuthorizerOption cấu hình hành vi tạo Authorizer/PolicyManager, truyền
// variadic vào cuối các factory function (tương thích ngược với call site cũ
// không truyền option nào).
type AuthorizerOption interface{ apply(*authorizerConfig) }

type authorizerOptFunc func(*authorizerConfig)

func (f authorizerOptFunc) apply(c *authorizerConfig) { f(c) }

// WithoutExpressionCache tắt cache expression, quay lại parse rule từ text ở
// mỗi lần đánh giá (hành vi trước khi có cache). Dùng làm kill-switch khi cần
// loại trừ cache là nguyên nhân một sự cố phân quyền.
func WithoutExpressionCache() AuthorizerOption {
	return authorizerOptFunc(func(c *authorizerConfig) { c.disableExpressionCache = true })
}

// ===== Trace types (optional reasoning) =====

type PredicateEvaluation struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments"`
	Result    bool              `json:"result"`
}

type RuleMatch struct {
	PolicyID string `json:"policy_id"`
	RuleID   string `json:"rule_id"`
	Matched  bool   `json:"matched"`
}

type AttributeAccess struct {
	Scope        string `json:"scope"` // subject | resource | env
	Path         string `json:"path"`
	ValuePreview string `json:"value_preview"`
}

type DecisionTrace struct {
	MatchedPolicies     []RuleMatch           `json:"matched_policies"`
	Predicates          []PredicateEvaluation `json:"predicates"`
	AttributesEvaluated []AttributeAccess     `json:"attributes_evaluated"`
	EvaluationMs        int64                 `json:"evaluation_ms"`
	EngineVersion       string                `json:"engine_version"`
	Error               string                `json:"error,omitempty"`
}

type TraceObserver interface {
	OnPredicate(name string, args []interface{}, result bool)
	OnRuleEvaluated(policyID, ruleID string, matched bool)
	OnAttributeRead(scope, path string, value interface{})
}

type redactorFunc func(scope, path string, raw interface{}) string

type traceConfig struct {
	enablePredicateTracing bool
	enableAttributeTracing bool
	maxItems               int
	redactor               redactorFunc
	engineVersion          string
}

type TraceOption interface{ apply(*traceConfig) }

type traceOptFunc func(*traceConfig)

func (f traceOptFunc) apply(c *traceConfig) { f(c) }

func WithPredicateTracing(enabled bool) TraceOption {
	return traceOptFunc(func(c *traceConfig) { c.enablePredicateTracing = enabled })
}
func WithAttributeTracing(enabled bool) TraceOption {
	return traceOptFunc(func(c *traceConfig) { c.enableAttributeTracing = enabled })
}
func WithMaxItems(n int) TraceOption {
	return traceOptFunc(func(c *traceConfig) {
		if n > 0 {
			c.maxItems = n
		}
	})
}
func WithRedactor(fn redactorFunc) TraceOption {
	return traceOptFunc(func(c *traceConfig) {
		if fn != nil {
			c.redactor = fn
		}
	})
}

func defaultRedactor(scope, path string, raw interface{}) string {
	const max = 64
	s := fmt.Sprint(raw)
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

const defaultEngineVersion = "go-abac-library/1.0.0"

// traceCollector cài đặt TraceObserver, tuân theo maxItems và redactor
type traceCollector struct {
	cfg       *traceConfig
	trace     *DecisionTrace
	predCount int
	attrCount int
	ruleCount int
}

func newTraceCollector(opts ...TraceOption) (*traceCollector, *DecisionTrace, *traceConfig) {
	cfg := &traceConfig{
		enablePredicateTracing: true,
		enableAttributeTracing: false,
		maxItems:               200,
		redactor:               defaultRedactor,
		engineVersion:          defaultEngineVersion,
	}
	for _, o := range opts {
		o.apply(cfg)
	}
	t := &DecisionTrace{
		MatchedPolicies:     make([]RuleMatch, 0, 8),
		Predicates:          make([]PredicateEvaluation, 0, 32),
		AttributesEvaluated: make([]AttributeAccess, 0, 32),
		EngineVersion:       cfg.engineVersion,
	}
	return &traceCollector{cfg: cfg, trace: t}, t, cfg
}

func (c *traceCollector) OnPredicate(name string, args []interface{}, result bool) {
	if c == nil || c.trace == nil || !c.cfg.enablePredicateTracing {
		return
	}
	if c.cfg.maxItems > 0 && c.predCount >= c.cfg.maxItems {
		return
	}
	argMap := make(map[string]string, len(args))
	for i, a := range args {
		key := fmt.Sprintf("arg%d", i)
		argMap[key] = c.cfg.redactor("predicate", name, a)
	}
	c.trace.Predicates = append(c.trace.Predicates, PredicateEvaluation{
		Name:      name,
		Arguments: argMap,
		Result:    result,
	})
	c.predCount++
}

func (c *traceCollector) OnRuleEvaluated(policyID, ruleID string, matched bool) {
	if c == nil || c.trace == nil {
		return
	}
	if c.cfg.maxItems > 0 && c.ruleCount >= c.cfg.maxItems {
		return
	}
	c.trace.MatchedPolicies = append(c.trace.MatchedPolicies, RuleMatch{
		PolicyID: policyID,
		RuleID:   ruleID,
		Matched:  matched,
	})
	c.ruleCount++
}

func (c *traceCollector) OnAttributeRead(scope, path string, value interface{}) {
	if c == nil || c.trace == nil || !c.cfg.enableAttributeTracing {
		return
	}
	if c.cfg.maxItems > 0 && c.attrCount >= c.cfg.maxItems {
		return
	}
	c.trace.AttributesEvaluated = append(c.trace.AttributesEvaluated, AttributeAccess{
		Scope:        scope,
		Path:         path,
		ValuePreview: c.cfg.redactor(scope, path, value),
	})
	c.attrCount++
}

// =========================================================================
// == Các hàm khởi tạo hệ thống (Factory Functions)
// =========================================================================

// NewABACSystemFromFile khởi tạo hệ thống từ file model và file policy.
func NewABACSystemFromFile(modelPath, policyPath string, sf SubjectFetcher, rf ResourceFetcher, customFunc CustomFunctionMap, opts ...AuthorizerOption) (*Authorizer, *PolicyManager, error) {
	e, err := casbin.NewSyncedEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enforcer from file: %w", err)
	}
	return newSystemWithEnforcer(e, sf, rf, customFunc, opts...)
}

// NewABACSystemFromDB khởi tạo hệ thống với policy được nạp từ database.
func NewABACSystemFromDB(modelPath string, db *gorm.DB, sf SubjectFetcher, rf ResourceFetcher, customFunc CustomFunctionMap, opts ...AuthorizerOption) (*Authorizer, *PolicyManager, error) {
	gormadapter.TurnOffAutoMigrate(db)
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gorm adapter: %w", err)
	}
	e, err := casbin.NewSyncedEnforcer(modelPath, adapter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enforcer from adapter: %w", err)
	}
	if err := e.LoadPolicy(); err != nil {
		return nil, nil, fmt.Errorf("failed to load policy from database: %w", err)
	}
	return newSystemWithEnforcer(e, sf, rf, customFunc, opts...)
}

// NewABACSystemFromDBUseTableName khởi tạo hệ thống từ DB với một tên bảng tùy chỉnh.
func NewABACSystemFromDBUseTableName(
	modelPath string,
	db *gorm.DB,
	preFix string,
	tableName string,
	sf SubjectFetcher,
	rf ResourceFetcher,
	customFunc map[string]govaluate.ExpressionFunction,
	opts ...AuthorizerOption,
) (*Authorizer, *PolicyManager, error) {
	gormadapter.TurnOffAutoMigrate(db)
	adapter, err := gormadapter.NewAdapterByDBUseTableName(db, preFix, tableName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gorm adapter with table name %s: %w", tableName, err)
	}

	e, err := casbin.NewSyncedEnforcer(modelPath, adapter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	if err := e.LoadPolicy(); err != nil {
		return nil, nil, fmt.Errorf("failed to load policy from database: %w", err)
	}
	return newSystemWithEnforcer(e, sf, rf, customFunc, opts...)
}

// NewABACSystemFromStrings khởi tạo hệ thống từ các chuỗi model và policy trong bộ nhớ.
func NewABACSystemFromStrings(modelStr, policyStr string, sf SubjectFetcher, rf ResourceFetcher, customFunc CustomFunctionMap, opts ...AuthorizerOption) (*Authorizer, *PolicyManager, error) {
	m, err := model.NewModelFromString(modelStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create model from string: %w", err)
	}
	e, err := casbin.NewSyncedEnforcer(m)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enforcer from model object: %w", err)
	}

	// Tự parse chuỗi policy và thêm vào enforcer
	scanner := bufio.NewScanner(strings.NewReader(policyStr))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Bỏ qua dòng trống và comment
		}
		parts := strings.Split(line, ",")
		if len(parts) > 1 && strings.TrimSpace(parts[0]) == "p" {
			policy := make([]string, 0, len(parts)-1)
			for i := 1; i < len(parts); i++ {
				policy = append(policy, strings.TrimSpace(parts[i]))
			}
			if _, err := e.AddPolicy(policy); err != nil {
				return nil, nil, fmt.Errorf("failed to add policy from string: %w", err)
			}
		}
	}

	return newSystemWithEnforcer(e, sf, rf, customFunc, opts...)
}

// CustomFunctionMap định nghĩa một map chứa các hàm tùy chỉnh mà người dùng muốn thêm.
// Key là tên hàm sẽ dùng trong policy, Value là hàm Go tương ứng.

// newSystemWithEnforcer là hàm private để hoàn tất việc khởi tạo, tránh lặp code.
func newSystemWithEnforcer(e *casbin.SyncedEnforcer, sf SubjectFetcher, rf ResourceFetcher, customFunction CustomFunctionMap, opts ...AuthorizerOption) (*Authorizer, *PolicyManager, error) {
	cfg := &authorizerConfig{}
	for _, o := range opts {
		o.apply(cfg)
	}

	// Tạo một instance của evaluator, truyền map custom function vào.
	evaluator := &expressionEvaluator{
		userFunctions: customFunction,
	}
	var cache *expressionCache
	if !cfg.disableExpressionCache {
		cache = newExpressionCache(customFunction)
		evaluator.cache = cache
	}

	// Đăng ký phương thức Evaluate của INSTANCE evaluator đó.
	e.AddFunction("evaluate", evaluator.Evaluate)
	authorizer := &Authorizer{
		enforcer:        e,
		subjectFetcher:  sf,
		resourceFetcher: rf,
		cache:           cache,
	}
	policyManager := &PolicyManager{
		enforcer: e,
		cache:    cache,
	}
	return authorizer, policyManager, nil
}

// =========================================================================
// == Các thành phần cốt lõi
// =========================================================================

// Check là hàm chính để kiểm tra quyền truy cập.
func (a *Authorizer) Check(ctx *context.Context, tenantID string, subject interface{}, resource interface{}, action string, envAttrsInput *Attributes) (bool, error) {
	subAttrs, err := a.subjectFetcher.GetSubjectAttributes(ctx, subject)
	if err != nil {
		return false, fmt.Errorf("subject attributes error: %w", err)
	}

	// Nếu envAttrs từ bên ngoài là nil, khởi tạo một map rỗng.
	var envAttrs Attributes
	if envAttrsInput != nil {
		envAttrs = *envAttrsInput
	} else {
		envAttrs = make(Attributes)
	}

	listResAttrs, err := a.resourceFetcher.GetResourceAttributes(ctx, resource)
	if err != nil {
		return false, fmt.Errorf("resource attributes error: %w", err)
	}

	return a.enforceOne(tenantID, subAttrs, listResAttrs, action, envAttrs)
}

// CheckMany chấm nhiều action trên CÙNG subject và resource. Khác với gọi
// Check() N lần, attribute (subject + resource) được nạp đúng MỘT lần rồi
// dùng lại cho mọi action — Enforce vẫn chạy N lần vì mỗi action là một
// quyết định độc lập. Kết quả trả về theo đúng thứ tự actions (results[i]
// ứng với actions[i]).
//
// Lỗi nạp attribute (subject hoặc resource) làm hỏng cả cụm: không có gì để
// chấm. Lỗi Enforce ở bất kỳ action nào cũng làm hỏng cả cụm — nhất quán với
// Check/PEP: một rule hỏng nghĩa là engine không đáng tin cho tenant đó ở
// thời điểm này, không nên âm thầm trả false riêng cho action đó.
//
// Không mở API nhận attribute từ bên ngoài: subject/resource vẫn phải đi qua
// fetcher như Check, giữ bất biến "attribute chỉ đến từ fetcher".
func (a *Authorizer) CheckMany(ctx *context.Context, tenantID string, subject interface{}, resource interface{}, actions []string, envAttrsInput *Attributes) ([]bool, error) {
	subAttrs, err := a.subjectFetcher.GetSubjectAttributes(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("subject attributes error: %w", err)
	}

	var envAttrs Attributes
	if envAttrsInput != nil {
		envAttrs = *envAttrsInput
	} else {
		envAttrs = make(Attributes)
	}

	listResAttrs, err := a.resourceFetcher.GetResourceAttributes(ctx, resource)
	if err != nil {
		return nil, fmt.Errorf("resource attributes error: %w", err)
	}

	results := make([]bool, len(actions))
	for i, action := range actions {
		allowed, err := a.enforceOne(tenantID, subAttrs, listResAttrs, action, envAttrs)
		if err != nil {
			return nil, fmt.Errorf("enforce action %q error: %w", action, err)
		}
		results[i] = allowed
	}
	return results, nil
}

// enforceOne chấm một action trên attribute ĐÃ NẠP SẴN (subject + danh sách
// resource) — không tự fetch. Đây là ruột dùng chung giữa Check (fetch rồi
// gọi 1 lần) và CheckMany (fetch rồi gọi N lần), gồm cả nhánh resource rỗng
// và nhánh AND đa resource (mọi resource phải allow thì hành động mới allow).
func (a *Authorizer) enforceOne(tenantID string, subAttrs Attributes, listResAttrs []Attributes, action string, envAttrs Attributes) (bool, error) {
	if listResAttrs == nil || len(listResAttrs) == 0 {
		request := &AuthorizationRequest{
			Subject:  subAttrs,
			Resource: Attributes{},
			Action:   action,
			Env:      envAttrs,
		}
		allowed, err := a.enforcer.Enforce(tenantID, request)
		if err != nil || !allowed {
			return false, err
		}
		return allowed, nil
	}

	for _, resAttribute := range listResAttrs {
		request := &AuthorizationRequest{
			Subject:  subAttrs,
			Resource: resAttribute,
			Action:   action,
			Env:      envAttrs,
		}
		allowed, err := a.enforcer.Enforce(tenantID, request)
		if err != nil || !allowed {
			return false, err
		}
	}
	return true, nil
}

// CheckWithTrace: kiểm tra quyền + trả về DecisionTrace (reasoning)
func (a *Authorizer) CheckWithTrace(ctx *context.Context, tenantID string, subject interface{}, resource interface{}, action string, envAttrsInput *Attributes, opts ...TraceOption) (bool, *DecisionTrace, error) {
	start := time.Now()
	collector, trace, cfg := newTraceCollector(opts...)

	subAttrs, err := a.subjectFetcher.GetSubjectAttributes(ctx, subject)
	if err != nil {
		trace.Error = fmt.Sprintf("subject attributes error: %v", err)
		trace.EvaluationMs = time.Since(start).Milliseconds()
		return false, trace, fmt.Errorf("subject attributes error: %w", err)
	}

	var envAttrs Attributes
	if envAttrsInput != nil {
		envAttrs = *envAttrsInput
	} else {
		envAttrs = make(Attributes)
	}

	listResAttrs, err := a.resourceFetcher.GetResourceAttributes(ctx, resource)
	if err != nil {
		trace.Error = fmt.Sprintf("resource attributes error: %v", err)
		trace.EvaluationMs = time.Since(start).Milliseconds()
		return false, trace, fmt.Errorf("resource attributes error: %w", err)
	}

	// Ghi nhận attributes cấp 1 nếu bật attribute tracing
	if cfg.enableAttributeTracing {
		for k, v := range subAttrs {
			collector.OnAttributeRead("subject", k, v)
		}
		for k, v := range envAttrs {
			collector.OnAttributeRead("env", k, v)
		}
	}

	if listResAttrs == nil || len(listResAttrs) == 0 {
		req := &AuthorizationRequest{
			Subject:  subAttrs,
			Resource: Attributes{},
			Action:   action,
			Env:      envAttrs,
			Trace:    collector,
			TraceCfg: cfg,
		}
		allowed, err := a.enforcer.Enforce(tenantID, req)
		trace.EvaluationMs = time.Since(start).Milliseconds()
		if err != nil {
			trace.Error = err.Error()
			return false, trace, err
		}
		return allowed, trace, nil
	}

	for _, resAttribute := range listResAttrs {
		if cfg.enableAttributeTracing {
			for k, v := range resAttribute {
				collector.OnAttributeRead("resource", k, v)
			}
		}
		req := &AuthorizationRequest{
			Subject:  subAttrs,
			Resource: resAttribute,
			Action:   action,
			Env:      envAttrs,
			Trace:    collector,
			TraceCfg: cfg,
		}
		allowed, err := a.enforcer.Enforce(tenantID, req)
		if err != nil {
			trace.Error = err.Error()
			trace.EvaluationMs = time.Since(start).Milliseconds()
			return false, trace, err
		}
		if !allowed {
			trace.EvaluationMs = time.Since(start).Milliseconds()
			return false, trace, nil
		}
	}

	trace.EvaluationMs = time.Since(start).Milliseconds()
	return true, trace, nil
}

// AuthorizationRequest chứa tất cả thông tin cho một yêu cầu phân quyền.
type AuthorizationRequest struct {
	Subject  Attributes
	Resource Attributes
	Action   string
	Env      Attributes

	// Optional tracing
	Trace    TraceObserver
	TraceCfg *traceConfig
}

// evaluateFunc là hàm tùy chỉnh của Casbin để đánh giá các biểu thức.
// Evaluate là phương thức thực hiện việc đánh giá, có chữ ký đúng chuẩn.
// args: ruleStr string, req *AuthorizationRequest, [policyID string], [ruleID string]
func (ev *expressionEvaluator) Evaluate(args ...interface{}) (interface{}, error) {
	if len(args) < 2 {
		return false, errors.New("evaluate: yêu cầu >= 2 tham số (rule, request [,policyID, ruleID])")
	}
	ruleStr, ok := args[0].(string)
	if !ok {
		return false, errors.New("evaluate: tham số đầu tiên phải là chuỗi (rule)")
	}
	req, ok := args[1].(*AuthorizationRequest)
	if !ok {
		return false, errors.New("evaluate: tham số thứ hai phải là *AuthorizationRequest")
	}

	var policyID, ruleID string
	if len(args) >= 3 {
		if v, ok := args[2].(string); ok {
			policyID = v
		}
	}
	if len(args) >= 4 {
		if v, ok := args[3].(string); ok {
			ruleID = v
		}
	}

	if ev.cache == nil {
		return ev.evaluateUncached(ruleStr, req, policyID, ruleID)
	}
	return ev.evaluateCached(ruleStr, req, policyID, ruleID)
}

// wrappedFunctionsForRequest kết hợp userFunctions với wrapper trace predicate
// (nếu request có bật predicate tracing). Wrapper ở đây capture trực tiếp
// `req` — CHỈ an toàn khi expression được tạo mới ngay trong lần gọi này và
// không bị tái sử dụng cho request khác (đường evaluateUncached). Đường có
// cache (evaluateCached, expression_cache.go) KHÔNG dùng hàm này — nó wrap
// theo slot observer ổn định để tránh rò rỉ trace giữa các request.
func (ev *expressionEvaluator) wrappedFunctionsForRequest(req *AuthorizationRequest) CustomFunctionMap {
	allFunctions := make(CustomFunctionMap)
	if ev.userFunctions != nil {
		for name, function := range ev.userFunctions {
			allFunctions[name] = function
		}
	}

	if req != nil && req.Trace != nil && req.TraceCfg != nil && req.TraceCfg.enablePredicateTracing {
		wrapped := make(CustomFunctionMap, len(allFunctions))
		for name, fn := range allFunctions {
			n := name
			orig := fn
			wrapped[n] = func(fnArgs ...interface{}) (interface{}, error) {
				res, err := orig(fnArgs...)
				// best effort cast
				boolRes := false
				if b, ok := res.(bool); ok {
					boolRes = b
				}
				req.Trace.OnPredicate(n, fnArgs, boolRes)
				return res, err
			}
		}
		allFunctions = wrapped
	}
	return allFunctions
}

// evaluateUncached parse ruleStr từ text ở MỌI lần gọi — hành vi gốc trước khi
// có cache. Giữ lại làm oracle cho differential test (expression_cache_test.go)
// và làm đường thoát khi WithoutExpressionCache() được bật.
func (ev *expressionEvaluator) evaluateUncached(ruleStr string, req *AuthorizationRequest, policyID, ruleID string) (interface{}, error) {
	// Kết hợp các hàm, có thể wrap để trace predicate
	allFunctions := ev.wrappedFunctionsForRequest(req)

	// Khởi tạo bộ đánh giá biểu thức với BỘ HÀM ĐÃ KẾT HỢP
	expr, err := govaluate.NewEvaluableExpressionWithFunctions(ruleStr, allFunctions)
	if err != nil {
		return false, fmt.Errorf("invalid rule syntax '%s': %w", ruleStr, err)
	}

	return evaluateParsedExpr(expr, req, ruleStr, policyID, ruleID)
}

// evaluateParsedExpr chạy expr đã parse với attributes của req, rồi ghi nhận
// rule matched vào trace nếu có. Dùng chung cho cả đường cache và không cache
// để hai đường không lệch logic ngoài phần parse.
func evaluateParsedExpr(expr *govaluate.EvaluableExpression, req *AuthorizationRequest, ruleStr, policyID, ruleID string) (interface{}, error) {
	parameters := map[string]interface{}{
		"Subject":  req.Subject,
		"Resource": req.Resource,
		"Action":   req.Action,
		"Env":      req.Env,
	}

	result, err := expr.Evaluate(parameters)
	if err != nil {
		return false, fmt.Errorf("evaluate: lỗi khi đánh giá rule '%s': %w", ruleStr, err)
	}

	// Ghi nhận rule matched nếu có thông tin policy/rule id
	if req != nil && req.Trace != nil && (policyID != "" || ruleID != "") {
		matched := false
		if b, ok := result.(bool); ok {
			matched = b
		}
		req.Trace.OnRuleEvaluated(policyID, ruleID, matched)
	}

	return result, nil
}
