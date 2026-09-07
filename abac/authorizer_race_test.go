// file: go-abac-library/abac/authorizer_race_test.go
package abac_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/duclek15/go-abac-library/abac"
	"github.com/duclek15/go-abac-library/internal/mocks"
)

// Hai tập policy khác nhau, đủ để LoadPolicy thay đổi model thật sự giữa
// các lần nạp (không phải nạp lại y hệt nội dung cũ).
const raceRuleSetA = `
p, *, "Action == 'approve_level_2' && hasGlobalRole(Subject, 'root')", allow
p, tenant1, "Action == 'approve_level_2' && hasTenantRole(Subject, 'tenant1', 'hr_manager')", allow
`

const raceRuleSetB = `
p, *, "Action == 'approve_level_2' && hasGlobalRole(Subject, 'root')", allow
p, tenant1, "Action == 'approve_level_2' && hasTenantRole(Subject, 'tenant1', 'hr_manager')", allow
p, tenant2, "Action == 'approve_level_2' && hasTenantRole(Subject, 'tenant2', 'hr_manager') && Resource.department == 'hr'", allow
`

func raceTestFunctions() abac.CustomFunctionMap {
	fns := make(abac.CustomFunctionMap)
	fns["has"] = abac.HasFunc
	fns["intersects"] = abac.IntersectsFunc
	fns["isIpInCidr"] = abac.IsIpInCidrFunc
	fns["matches"] = abac.MatchesFunc
	fns["isBusinessHours"] = abac.IsBusinessHoursFunc
	fns["hasGlobalRole"] = abac.HasGlobalRoleFunc
	fns["hasTenantRole"] = abac.HasTenantRoleFunc
	fns["hasOrgRole"] = abac.HasOrgRoleFunc
	return fns
}

// atomicWritePolicy ghi nội dung policy mới bằng write-then-rename để adapter
// luôn đọc được một file trọn vẹn (không đọc trúng file đang ghi dở).
func atomicWritePolicy(t *testing.T, policyPath, content string, goroutineIdx, iter int) {
	t.Helper()
	tmpPath := fmt.Sprintf("%s.tmp.%d.%d", policyPath, goroutineIdx, iter)
	if err := os.WriteFile(tmpPath, []byte(content), 0o644); err != nil {
		t.Errorf("write temp policy file: %v", err)
		return
	}
	if err := os.Rename(tmpPath, policyPath); err != nil {
		t.Errorf("rename temp policy file: %v", err)
	}
}

// TestAuthorizerConcurrentLoadPolicyAndCheck_Race chứng minh (hoặc bác bỏ, sau
// khi sửa) race giữa PolicyManager.LoadPoliciesFromStorage (ghi model) và
// Authorizer.Check/CheckWithTrace (đọc model) khi chạy đồng thời trên cùng một
// enforcer singleton — đúng kịch bản thật của reconciler nền + PEP mỗi request.
//
// Trên code TRƯỚC khi sửa (casbin.NewEnforcer, không khoá): `go test -race`
// phải báo DATA RACE. Sau khi đổi sang casbin.NewSyncedEnforcer: xanh.
func TestAuthorizerConcurrentLoadPolicyAndCheck_Race(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.csv")
	if err := os.WriteFile(policyPath, []byte(raceRuleSetA), 0o644); err != nil {
		t.Fatalf("seed policy file: %v", err)
	}

	mockFetcher := &mocks.MockFetcher{}
	authorizer, policyManager, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf",
		policyPath,
		mockFetcher,
		mockFetcher,
		raceTestFunctions(),
	)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	const (
		numCheckers  = 16
		numTracers   = 8
		numLoaders   = 6
		iterations   = 400
		loaderRounds = 200
	)

	subjects := []string{"root_user", "t1_hr_manager", "t2_hr_manager", "unknown_user"}
	resources := []string{"t1_eng_request", "t2_hr_request", "t2_sales_request"}

	ctx := context.Background()
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Goroutine đọc: gọi Check liên tục.
	for i := 0; i < numCheckers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for iter := 0; ; iter++ {
				select {
				case <-stop:
					return
				default:
				}
				subject := subjects[(idx+iter)%len(subjects)]
				resource := resources[(idx+iter)%len(resources)]
				_, _ = authorizer.Check(&ctx, "tenant1", subject, resource, "approve_level_2", nil)
				if iter >= iterations {
					return
				}
			}
		}(i)
	}

	// Goroutine đọc: gọi CheckWithTrace liên tục (đường vào khác của cùng enforcer).
	for i := 0; i < numTracers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for iter := 0; ; iter++ {
				select {
				case <-stop:
					return
				default:
				}
				subject := subjects[(idx+iter)%len(subjects)]
				resource := resources[(idx+iter)%len(resources)]
				_, _, _ = authorizer.CheckWithTrace(&ctx, "tenant2", subject, resource, "approve_level_2", nil,
					abac.WithPredicateTracing(true), abac.WithAttributeTracing(true))
				if iter >= iterations {
					return
				}
			}
		}(i)
	}

	// Goroutine ghi: LoadPoliciesFromStorage với nội dung khác nhau mỗi lần.
	for i := 0; i < numLoaders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for iter := 0; iter < loaderRounds; iter++ {
				content := raceRuleSetA
				if (idx+iter)%2 == 0 {
					content = raceRuleSetB
				}
				atomicWritePolicy(t, policyPath, content, idx, iter)
				if err := policyManager.LoadPoliciesFromStorage(); err != nil {
					t.Errorf("LoadPoliciesFromStorage: %v", err)
				}
			}
		}(i)
	}

	// An toàn: không để test treo vô hạn nếu có deadlock bất ngờ.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		close(stop)
		t.Fatal("race test treo quá 30s — nghi ngờ deadlock, không phải race đơn thuần")
	}
}

// differentialCorpus: 5 rule thật, dùng các hàm built-in CÓ THẬT của thư viện
// (hasGlobalRole/hasTenantRole) thay vì corpus mẫu ở
// backend_go/migrations/postgresql/20260421000100_seed_finance_user_abac_policies.sql
// — file đó dùng các hàm chỉ định nghĩa bên backend (hasAnyOrgRole,
// belongsToResourceOrg, checkNestedSliceFunc, isResourceOwner), không tồn tại
// trong go-abac-library. Tự chế bản giả cho các hàm đó chỉ để chạy test sẽ vi
// phạm "không thêm fake/shortcut để qua check", nên dùng corpus tối thiểu thật
// của chính thư viện (cho phép theo bước 6 của phase file) — 5 rule thật, có
// allow lẫn deny, dùng đúng hàm built-in đã kiểm chứng ở TestAuthorizer_MultiTenant.
const differentialCorpus = `
p, *, "Action == 'approve_level_2' && hasGlobalRole(Subject, 'root')", allow
p, tenant1, "Action == 'approve_level_2' && hasTenantRole(Subject, 'tenant1', 'hr_manager')", allow
p, tenant2, "Action == 'approve_level_2' && hasTenantRole(Subject, 'tenant2', 'hr_manager') && Resource.department == 'hr'", allow
p, *, "Action == 'view_directory' && hasTenantRole(Subject, 'tenant1', 'hr_manager')", allow
p, tenant2, "Action == 'approve_level_2' && hasTenantRole(Subject, 'tenant2', 'hr_manager') && Resource.department == 'sales'", deny
`

// TestAuthorizerEnforceDifferential_FixedCorpus khoá lại kết quả Enforce() cho
// một corpus cố định (5 rule, có allow lẫn deny-override). Chạy test này trước
// và sau khi đổi sang SyncedEnforcer phải cho kết quả giống hệt — vì
// SyncedEnforcer chỉ bọc RWMutex quanh lời gọi tới *Enforcer.Enforce() gốc,
// không đổi logic đánh giá.
func TestAuthorizerEnforceDifferential_FixedCorpus(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "differential_policy.csv")
	if err := os.WriteFile(policyPath, []byte(differentialCorpus), 0o644); err != nil {
		t.Fatalf("seed policy file: %v", err)
	}

	mockFetcher := &mocks.MockFetcher{}
	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf",
		policyPath,
		mockFetcher,
		mockFetcher,
		raceTestFunctions(),
	)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	ctx := context.Background()
	testCases := []struct {
		name       string
		tenantID   string
		subjectID  string
		resourceID string
		action     string
		expected   bool
	}{
		{"root luôn được duyệt ở mọi tenant (rule #1)", "tenant2", "root_user", "t2_sales_request", "approve_level_2", true},
		{"T1 HR Manager duyệt đơn Engineering trong T1 (rule #2)", "tenant1", "t1_hr_manager", "t1_eng_request", "approve_level_2", true},
		{"T2 HR Manager duyệt đơn HR trong T2 (rule #3)", "tenant2", "t2_hr_manager", "t2_hr_request", "approve_level_2", true},
		{"T2 HR Manager bị deny tường minh với đơn Sales (rule #5 deny-override)", "tenant2", "t2_hr_manager", "t2_sales_request", "approve_level_2", false},
		{"T1 HR Manager không được duyệt ở tenant2 (sai tenant)", "tenant2", "t1_hr_manager", "t2_hr_request", "approve_level_2", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := authorizer.Check(&ctx, tc.tenantID, tc.subjectID, tc.resourceID, tc.action, nil)
			if err != nil {
				t.Fatalf("Check trả lỗi không mong đợi: %v", err)
			}
			if allowed != tc.expected {
				t.Errorf("Check(%q,%q,%q,%q) = %v, muốn %v", tc.tenantID, tc.subjectID, tc.resourceID, tc.action, allowed, tc.expected)
			}
		})
	}
}

// BenchmarkAuthorizerEnforce đo chi phí một lần Check() (1 action, 1 resource)
// — dùng để so sánh trước/sau khi đổi sang casbin.NewSyncedEnforcer. Chưa có
// cache expression (đó là việc của Phase 2), nên số đo ở đây cô lập đúng một
// biến: chi phí khoá thêm vào.
func BenchmarkAuthorizerEnforce(b *testing.B) {
	mockFetcher := &mocks.MockFetcher{}
	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf",
		"../casbin_config/abac_policy.csv",
		mockFetcher,
		mockFetcher,
		raceTestFunctions(),
	)
	if err != nil {
		b.Fatalf("failed to create authorizer: %v", err)
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := authorizer.Check(&ctx, "tenant1", "t1_hr_manager", "t1_eng_request", "approve_level_2", nil); err != nil {
			b.Fatalf("Check failed: %v", err)
		}
	}
}
