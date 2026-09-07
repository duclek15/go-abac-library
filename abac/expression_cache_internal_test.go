// file: go-abac-library/abac/expression_cache_internal_test.go
//
// Test nội bộ (package abac, white-box) cho expression_cache.go — cần truy
// cập trực tiếp field/method không export (expressionCache.len,
// Authorizer.cache, PolicyManager.cache) để khẳng định eviction thật sự
// chạy, không phải suy luận gián tiếp qua hành vi Check/CheckWithTrace.
package abac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestExpressionCache_GetPool_ErrorNotCached khẳng định lỗi parse KHÔNG được
// lưu vào cache map — rule hỏng phải báo lỗi ở MỌI lần gọi (không phải chỉ
// lần đầu rồi im lặng những lần sau), và một rule lỗi không làm hỏng cache
// cho các rule đúng khác.
func TestExpressionCache_GetPool_ErrorNotCached(t *testing.T) {
	cache := newExpressionCache(CustomFunctionMap{})
	const badRule = "Action == " // thiếu vế phải, lỗi cú pháp

	if _, err := cache.getPool(badRule); err == nil {
		t.Fatalf("mong đợi lỗi parse cho rule hỏng, không có lỗi")
	}
	if _, err := cache.getPool(badRule); err == nil {
		t.Fatalf("lần gọi thứ 2 với cùng rule hỏng vẫn phải báo lỗi (không được cache lỗi parse)")
	}
	if got := cache.len(); got != 0 {
		t.Fatalf("cache phải rỗng khi chỉ gặp rule lỗi, len=%d", got)
	}

	if _, err := cache.getPool("Action == 'x'"); err != nil {
		t.Fatalf("rule hợp lệ không được báo lỗi: %v", err)
	}
	if got := cache.len(); got != 1 {
		t.Fatalf("cache phải có đúng 1 entry sau 1 rule hợp lệ, len=%d", got)
	}
}

// TestExpressionCache_EvictExcept khẳng định evictExcept dọn đúng entry
// không còn active, giữ nguyên entry còn active — cơ chế nền cho
// PolicyManager.syncExpressionCache.
func TestExpressionCache_EvictExcept(t *testing.T) {
	cache := newExpressionCache(CustomFunctionMap{})
	rules := []string{"Action == 'a'", "Action == 'b'", "Action == 'c'"}
	for _, r := range rules {
		if _, err := cache.getPool(r); err != nil {
			t.Fatalf("parse %q: %v", r, err)
		}
	}
	if got := cache.len(); got != 3 {
		t.Fatalf("len=%d, muốn 3", got)
	}

	evicted := cache.evictExcept(map[string]struct{}{"Action == 'b'": {}})
	if evicted != 2 {
		t.Fatalf("evictExcept trả %d, muốn 2", evicted)
	}
	if got := cache.len(); got != 1 {
		t.Fatalf("len=%d sau evict, muốn 1", got)
	}
	if _, ok := cache.entries.Load("Action == 'b'"); !ok {
		t.Fatalf("entry đang active 'Action == '\\''b'\\''' bị xoá nhầm")
	}

	// evictExcept với active rỗng (mô phỏng ClearAllPolicies) phải dọn sạch.
	evicted = cache.evictExcept(map[string]struct{}{})
	if evicted != 1 {
		t.Fatalf("evictExcept(rỗng) trả %d, muốn 1", evicted)
	}
	if got := cache.len(); got != 0 {
		t.Fatalf("len=%d sau evict toàn bộ, muốn 0", got)
	}
}

// alwaysFoundFetcher là fetcher tối giản luôn trả về attrs cố định, đủ để
// Authorizer.Check đi tới Enforce() (và do đó gọi evaluate()) mà không phải
// lo lỗi "not found" — dùng riêng cho test eviction, không quan tâm nội
// dung attrs.
type alwaysFoundFetcher struct{}

func (alwaysFoundFetcher) GetSubjectAttributes(_ *context.Context, _ interface{}) (Attributes, error) {
	return Attributes{"id": "u"}, nil
}

func (alwaysFoundFetcher) GetResourceAttributes(_ *context.Context, _ interface{}) ([]Attributes, error) {
	return []Attributes{{"id": "r"}}, nil
}

// TestPolicyManager_EvictsExpressionCacheOnPolicyChange nạp N (=30) tập rule
// KHÁC NHAU liên tiếp qua LoadPoliciesFromStorage (đúng kịch bản org-admin
// sửa policy nhiều lần) và khẳng định cache KHÔNG tăng dần theo N — đúng yêu
// cầu bắt buộc "eviction hoạt động" của phase. Mỗi vòng chỉ có ĐÚNG MỘT rule
// active nên nếu eviction hoạt động đúng, cache luôn ổn định ở đúng 1 entry
// sau khi Check() populate lại cho rule hiện tại; nếu eviction KHÔNG chạy,
// cache sẽ tăng dần lên tới 30 entry vào cuối vòng lặp.
func TestPolicyManager_EvictsExpressionCacheOnPolicyChange(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.csv")
	writeRule := func(rule string) {
		t.Helper()
		content := fmt.Sprintf("p, *, %q, allow\n", rule)
		if err := os.WriteFile(policyPath, []byte(content), 0o644); err != nil {
			t.Fatalf("ghi policy: %v", err)
		}
	}
	writeRule("Action == 'r0'")

	fetcher := alwaysFoundFetcher{}
	authorizer, policyManager, err := NewABACSystemFromFile(
		"../casbin_config/abac_model.conf", policyPath, fetcher, fetcher, CustomFunctionMap{},
	)
	if err != nil {
		t.Fatalf("tạo authorizer: %v", err)
	}
	if authorizer.cache == nil {
		t.Fatalf("cache phải bật mặc định (không truyền WithoutExpressionCache)")
	}

	ctx := context.Background()
	const rounds = 30
	for i := 1; i <= rounds; i++ {
		rule := fmt.Sprintf("Action == 'r%d'", i)
		writeRule(rule)
		if err := policyManager.LoadPoliciesFromStorage(); err != nil {
			t.Fatalf("LoadPoliciesFromStorage vòng %d: %v", i, err)
		}

		// Cache lấp lười — chỉ populate khi evaluate() thật sự chạy, không
		// phải lúc LoadPolicy. Gọi Check để buộc rule hiện tại được parse.
		if _, err := authorizer.Check(&ctx, "*", "u", "r", "any_action", nil); err != nil {
			t.Fatalf("Check vòng %d: %v", i, err)
		}

		if got := authorizer.cache.len(); got != 1 {
			t.Fatalf("vòng %d/%d: cache có %d entry, kỳ vọng đúng 1 (rule hiện tại) — cache đang phình theo N thay vì được dọn", i, rounds, got)
		}
	}
}

// TestPolicyManager_ClearAllPoliciesEvictsCache khẳng định ClearAllPolicies
// (active = rỗng) dọn sạch cache, không để lại entry mồ côi.
func TestPolicyManager_ClearAllPoliciesEvictsCache(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "empty_policy.csv")
	if err := os.WriteFile(policyPath, []byte{}, 0o644); err != nil {
		t.Fatalf("tạo file policy rỗng: %v", err)
	}

	fetcher := alwaysFoundFetcher{}
	authorizer, policyManager, err := NewABACSystemFromFile(
		"../casbin_config/abac_model.conf", policyPath, fetcher, fetcher, CustomFunctionMap{},
	)
	if err != nil {
		t.Fatalf("tạo authorizer: %v", err)
	}
	if _, err := policyManager.AddPolicy([]string{"*", "Action == 'x'", "allow"}); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	ctx := context.Background()
	if _, err := authorizer.Check(&ctx, "*", "u", "r", "any_action", nil); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got := authorizer.cache.len(); got != 1 {
		t.Fatalf("cache phải có 1 entry trước khi clear, có %d", got)
	}

	policyManager.ClearAllPolicies()
	if got := authorizer.cache.len(); got != 0 {
		t.Fatalf("cache phải rỗng sau ClearAllPolicies, còn %d entry", got)
	}
}

// TestAuthorizer_WithoutExpressionCache_DisablesCache khẳng định kill-switch
// tắt hẳn cache (field cache == nil trên cả Authorizer lẫn PolicyManager),
// và syncExpressionCache không panic khi cache đã tắt.
func TestAuthorizer_WithoutExpressionCache_DisablesCache(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.csv")
	if err := os.WriteFile(policyPath, []byte("p,*,\"Action == 'x'\",allow\n"), 0o644); err != nil {
		t.Fatalf("ghi policy: %v", err)
	}
	authorizer, policyManager, err := NewABACSystemFromFile(
		"../casbin_config/abac_model.conf", policyPath, alwaysFoundFetcher{}, alwaysFoundFetcher{}, CustomFunctionMap{},
		WithoutExpressionCache(),
	)
	if err != nil {
		t.Fatalf("tạo authorizer: %v", err)
	}
	if authorizer.cache != nil {
		t.Fatalf("Authorizer.cache phải nil khi dùng WithoutExpressionCache()")
	}
	if policyManager.cache != nil {
		t.Fatalf("PolicyManager.cache phải nil khi dùng WithoutExpressionCache()")
	}
	// Không được panic khi cache nil — mọi entrypoint mutate policy đều gọi
	// syncExpressionCache() vô điều kiện.
	policyManager.syncExpressionCache()
	if _, err := policyManager.AddPolicy([]string{"*", "Action == 'y'", "allow"}); err != nil {
		t.Fatalf("AddPolicy với cache tắt: %v", err)
	}
}
