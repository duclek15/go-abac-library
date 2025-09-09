// file: go-abac-library/abac/authorizer.go
package abac

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/casbin/govaluate"
	"gorm.io/gorm"
)

// Authorizer là PDP, chứa logic phân quyền.
type Authorizer struct {
	enforcer        *casbin.Enforcer
	subjectFetcher  SubjectFetcher
	resourceFetcher ResourceFetcher
}

type CustomFunctionMap map[string]govaluate.ExpressionFunction

// expressionEvaluator là một struct giữ trạng thái các hàm tùy chỉnh của người dùng.
type expressionEvaluator struct {
	userFunctions CustomFunctionMap
}

// =========================================================================
// == Các hàm khởi tạo hệ thống (Factory Functions)
// =========================================================================

// NewABACSystemFromFile khởi tạo hệ thống từ file model và file policy.
func NewABACSystemFromFile(modelPath, policyPath string, sf SubjectFetcher, rf ResourceFetcher, customFunc CustomFunctionMap) (*Authorizer, *PolicyManager, error) {
	e, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enforcer from file: %w", err)
	}
	return newSystemWithEnforcer(e, sf, rf, customFunc)
}

// NewABACSystemFromDB khởi tạo hệ thống với policy được nạp từ database.
func NewABACSystemFromDB(modelPath string, db *gorm.DB, sf SubjectFetcher, rf ResourceFetcher, customFunc CustomFunctionMap) (*Authorizer, *PolicyManager, error) {
	gormadapter.TurnOffAutoMigrate(db)
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gorm adapter: %w", err)
	}
	e, err := casbin.NewEnforcer(modelPath, adapter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enforcer from adapter: %w", err)
	}
	if err := e.LoadPolicy(); err != nil {
		return nil, nil, fmt.Errorf("failed to load policy from database: %w", err)
	}
	return newSystemWithEnforcer(e, sf, rf, customFunc)
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
) (*Authorizer, *PolicyManager, error) {
	gormadapter.TurnOffAutoMigrate(db)
	adapter, err := gormadapter.NewAdapterByDBUseTableName(db, preFix, tableName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gorm adapter with table name %s: %w", tableName, err)
	}

	e, err := casbin.NewEnforcer(modelPath, adapter)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create enforcer: %w", err)
	}
	if err := e.LoadPolicy(); err != nil {
		return nil, nil, fmt.Errorf("failed to load policy from database: %w", err)
	}
	return newSystemWithEnforcer(e, sf, rf, customFunc)
}

// NewABACSystemFromStrings khởi tạo hệ thống từ các chuỗi model và policy trong bộ nhớ.
func NewABACSystemFromStrings(modelStr, policyStr string, sf SubjectFetcher, rf ResourceFetcher, customFunc CustomFunctionMap) (*Authorizer, *PolicyManager, error) {
	m, err := model.NewModelFromString(modelStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create model from string: %w", err)
	}
	e, err := casbin.NewEnforcer(m)
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

	return newSystemWithEnforcer(e, sf, rf, customFunc)
}

// CustomFunctionMap định nghĩa một map chứa các hàm tùy chỉnh mà người dùng muốn thêm.
// Key là tên hàm sẽ dùng trong policy, Value là hàm Go tương ứng.

// newSystemWithEnforcer là hàm private để hoàn tất việc khởi tạo, tránh lặp code.
func newSystemWithEnforcer(e *casbin.Enforcer, sf SubjectFetcher, rf ResourceFetcher, customFunction CustomFunctionMap) (*Authorizer, *PolicyManager, error) {
	// Tạo một instance của evaluator, truyền map custom function vào.
	evaluator := &expressionEvaluator{
		userFunctions: customFunction,
	}

	// Đăng ký phương thức Evaluate của INSTANCE evaluator đó.
	e.AddFunction("evaluate", evaluator.Evaluate)
	authorizer := &Authorizer{
		enforcer:        e,
		subjectFetcher:  sf,
		resourceFetcher: rf,
	}
	policyManager := &PolicyManager{
		enforcer: e,
	}
	return authorizer, policyManager, nil
}

// =========================================================================
// == Các thành phần cốt lõi
// =========================================================================

// Check là hàm chính để kiểm tra quyền truy cập.
func (a *Authorizer) Check(ctx *context.Context, tenantID string, subjectID string, resourceID string, action string, envAttrs Attributes) (bool, error) {
	subAttrs, err := a.subjectFetcher.GetSubjectAttributes(ctx, subjectID, nil)
	if err != nil {
		return false, fmt.Errorf("subject attributes error: %w", err)
	}

	resAttrs, err := a.resourceFetcher.GetResourceAttributes(ctx, resourceID, nil)
	if err != nil {
		return false, fmt.Errorf("resource attributes error: %w", err)
	}

	// Nếu envAttrs từ bên ngoài là nil, khởi tạo một map rỗng.
	if envAttrs == nil {
		envAttrs = Attributes{}
	}

	// Bổ sung các thuộc tính môi trường do thư viện tự sinh ra.
	// Cách này cho phép ghi đè nếu cần thiết.
	if _, ok := envAttrs["timeOfDay"]; !ok {
		envAttrs["timeOfDay"] = time.Now().Hour()
	}

	request := &AuthorizationRequest{
		Subject:  subAttrs,
		Resource: resAttrs,
		Action:   action,
		Env:      envAttrs,
	}

	return a.enforcer.Enforce(tenantID, request)
}

// AuthorizationRequest chứa tất cả thông tin cho một yêu cầu phân quyền.
type AuthorizationRequest struct {
	Subject  Attributes
	Resource Attributes
	Action   string
	Env      Attributes
}

// evaluateFunc là hàm tùy chỉnh của Casbin để đánh giá các biểu thức.
// Evaluate là phương thức thực hiện việc đánh giá, có chữ ký đúng chuẩn.
func (ev *expressionEvaluator) Evaluate(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, errors.New("evaluate: yêu cầu 2 tham số (rule, request)")
	}
	ruleStr, ok := args[0].(string)
	if !ok {
		return false, errors.New("evaluate: tham số đầu tiên phải là chuỗi (rule)")
	}
	req, ok := args[1].(*AuthorizationRequest)
	if !ok {
		return false, errors.New("evaluate: tham số thứ hai phải là *AuthorizationRequest")
	}

	// Tạo một map chứa TẤT CẢ các hàm
	allFunctions := make(CustomFunctionMap)

	// 2. Thêm các hàm do người dùng cung cấp (có thể ghi đè hàm mặc định nếu trùng tên)
	if ev.userFunctions != nil {
		for name, function := range ev.userFunctions {
			allFunctions[name] = function
		}
	}

	// Khởi tạo bộ đánh giá biểu thức với BỘ HÀM ĐÃ KẾT HỢP
	expr, err := govaluate.NewEvaluableExpressionWithFunctions(ruleStr, allFunctions)
	if err != nil {
		return false, fmt.Errorf("invalid rule syntax '%s': %w", ruleStr, err)
	}

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

	return result, nil
}
