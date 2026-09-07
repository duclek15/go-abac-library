package abac

import "github.com/casbin/casbin/v2"

// PolicyManager đóng vai trò là PAP, cung cấp một giao diện hoàn chỉnh
// để quản lý các quy tắc policy trong bộ nhớ của Casbin.
//
// enforcer dùng *casbin.SyncedEnforcer — cùng một instance được chia sẻ với
// Authorizer (PDP) qua newSystemWithEnforcer. Xem ghi chú ở Authorizer.enforcer.
type PolicyManager struct {
	enforcer *casbin.SyncedEnforcer

	// cache là expression cache dùng chung với Authorizer (cùng instance, tạo
	// một lần trong newSystemWithEnforcer). PolicyManager dùng nó để dọn
	// (evict) entry theo sự kiện mỗi khi tập policy đổi — xem
	// syncExpressionCache. nil nếu Authorizer được tạo với
	// WithoutExpressionCache(), hoặc khi PolicyManager được dựng thủ công
	// (như trong test nội bộ) mà không đi qua factory.
	cache *expressionCache
}

// syncExpressionCache dọn cache expression theo đúng tập rule đang có hiệu
// lực trong enforcer, gọi sau mỗi lần enforcer đổi policy (thêm/sửa/xoá/nạp
// lại). Đây là cơ chế eviction ĐÃ CHỌN cho cache (thay vì LRU có trần): chính
// xác hơn LRU vì dọn đúng lúc org-admin đổi policy — không cần tham số trần
// bộ nhớ nào phải tinh chỉnh. Không làm gì nếu cache bị tắt (nil) hoặc không
// lấy được policy hiện tại (giữ nguyên cache cũ, ưu tiên không phá hành vi
// đang chạy hơn là dọn tuyệt đối chính xác — entry thừa tự hết hạn ở lần gọi
// kế tiếp thành công).
func (pm *PolicyManager) syncExpressionCache() {
	if pm.cache == nil {
		return
	}
	policies, err := pm.enforcer.GetPolicy()
	if err != nil {
		return
	}
	// Cột thứ 2 (index 1) của policy `p = tenant, rule, eft` là văn bản rule —
	// đúng bằng khóa cache (args[0] mà expressionEvaluator.Evaluate nhận được
	// từ matcher `evaluate(p.rule, r.req)`).
	active := make(map[string]struct{}, len(policies))
	for _, row := range policies {
		if len(row) >= 2 {
			active[row[1]] = struct{}{}
		}
	}
	pm.cache.evictExcept(active)
}

// =========================================================================
// == CREATE (Thêm mới)
// =========================================================================

// AddPolicy thêm một policy mới vào bộ nhớ. Trả về true nếu thành công.
// rule: []string{"Subject.role == 'manager'", "allow"}
func (pm *PolicyManager) AddPolicy(rule []string) (bool, error) {
	ok, err := pm.enforcer.AddPolicy(rule)
	pm.syncExpressionCache()
	return ok, err
}

// AddPolicies thêm nhiều policy mới vào bộ nhớ. Giao dịch nguyên tử.
func (pm *PolicyManager) AddPolicies(rules [][]string) (bool, error) {
	ok, err := pm.enforcer.AddPolicies(rules)
	pm.syncExpressionCache()
	return ok, err
}

// =========================================================================
// == READ (Đọc)
// =========================================================================

// GetPolicies trả về tất cả các policy hiện có.
func (pm *PolicyManager) GetPolicies() ([][]string, error) {
	return pm.enforcer.GetPolicy()
}

// GetFilteredPolicies trả về các policy được lọc theo điều kiện.
// Ví dụ: GetFilteredPolicies(1, "allow") sẽ trả về tất cả các rule có effect là "allow".
func (pm *PolicyManager) GetFilteredPolicies(fieldIndex int, fieldValues ...string) ([][]string, error) {
	return pm.enforcer.GetFilteredPolicy(fieldIndex, fieldValues...)
}

// HasPolicy kiểm tra policy đã tồn tại chưa.
func (pm *PolicyManager) HasPolicy(rule []string) (bool, error) {
	return pm.enforcer.HasPolicy(rule)
}

// =========================================================================
// == UPDATE (Cập nhật)
// =========================================================================

// UpdatePolicy cập nhật một policy cũ thành policy mới.
// Trả về true nếu policy cũ tồn tại và được cập nhật thành công.
func (pm *PolicyManager) UpdatePolicy(oldRule []string, newRule []string) (bool, error) {
	ok, err := pm.enforcer.UpdatePolicy(oldRule, newRule)
	pm.syncExpressionCache()
	return ok, err
}

// =========================================================================
// == DELETE (Xóa)
// =========================================================================

// RemovePolicy xóa một policy khỏi bộ nhớ.
// Trả về true nếu quy tắc tồn tại và được xóa thành công.
func (pm *PolicyManager) RemovePolicy(rule []string) (bool, error) {
	ok, err := pm.enforcer.RemovePolicy(rule)
	pm.syncExpressionCache()
	return ok, err
}

// RemovePolicies xóa nhiều policy khỏi bộ nhớ.
// Đây là một giao dịch nguyên tử (atomic).
func (pm *PolicyManager) RemovePolicies(rules [][]string) (bool, error) {
	ok, err := pm.enforcer.RemovePolicies(rules)
	pm.syncExpressionCache()
	return ok, err
}

// RemoveFilteredPolicy xóa các policy được lọc theo điều kiện.
// Trả về true nếu có quy tắc bị xóa.
func (pm *PolicyManager) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	ok, err := pm.enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
	pm.syncExpressionCache()
	return ok, err
}

// ClearAllPolicies xóa toàn bộ policy khỏi bộ nhớ.
func (pm *PolicyManager) ClearAllPolicies() {
	pm.enforcer.ClearPolicy()
	pm.syncExpressionCache()
}

// =========================================================================
// == SYNCHRONIZATION (Đồng bộ hóa với nguồn lưu trữ)
// =========================================================================

// SavePoliciesToStorage lưu policy hiện có xuống storage (file/DB).
// Hữu ích khi bạn muốn thực hiện nhiều thay đổi trong bộ nhớ trước rồi mới "commit".
func (pm *PolicyManager) SavePoliciesToStorage() error {
	return pm.enforcer.SavePolicy()
}

// LoadPoliciesFromStorage tải lại toàn bộ policy từ storage.
// Cần thiết để đồng bộ khi policy trong DB bị thay đổi bởi một hệ thống khác.
func (pm *PolicyManager) LoadPoliciesFromStorage() error {
	err := pm.enforcer.LoadPolicy()
	pm.syncExpressionCache()
	return err
}
