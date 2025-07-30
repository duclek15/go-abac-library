package abac

import "github.com/casbin/casbin/v2"

// PolicyManager đóng vai trò là PAP, cung cấp một giao diện hoàn chỉnh
// để quản lý các quy tắc policy trong bộ nhớ của Casbin.
type PolicyManager struct {
	enforcer *casbin.Enforcer
}

// =========================================================================
// == CREATE (Thêm mới)
// =========================================================================

// AddPolicy thêm một policy mới vào bộ nhớ. Trả về true nếu thành công.
// rule: []string{"Subject.role == 'manager'", "allow"}
func (pm *PolicyManager) AddPolicy(rule []string) (bool, error) {
	return pm.enforcer.AddPolicy(rule)
}

// AddPolicies thêm nhiều policy mới vào bộ nhớ. Giao dịch nguyên tử.
func (pm *PolicyManager) AddPolicies(rules [][]string) (bool, error) {
	return pm.enforcer.AddPolicies(rules)
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
	return pm.enforcer.UpdatePolicy(oldRule, newRule)
}

// =========================================================================
// == DELETE (Xóa)
// =========================================================================

// RemovePolicy xóa một policy khỏi bộ nhớ.
// Trả về true nếu quy tắc tồn tại và được xóa thành công.
func (pm *PolicyManager) RemovePolicy(rule []string) (bool, error) {
	return pm.enforcer.RemovePolicy(rule)
}

// RemovePolicies xóa nhiều policy khỏi bộ nhớ.
// Đây là một giao dịch nguyên tử (atomic).
func (pm *PolicyManager) RemovePolicies(rules [][]string) (bool, error) {
	return pm.enforcer.RemovePolicies(rules)
}

// RemoveFilteredPolicy xóa các policy được lọc theo điều kiện.
// Trả về true nếu có quy tắc bị xóa.
func (pm *PolicyManager) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	return pm.enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
}

// ClearAllPolicies xóa toàn bộ policy khỏi bộ nhớ.
func (pm *PolicyManager) ClearAllPolicies() {
	pm.enforcer.ClearPolicy()
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
	return pm.enforcer.LoadPolicy()
}
