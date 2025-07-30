# 4. The Policy Manager (PAP)

`PolicyManager` là giao diện để bạn tương tác với nơi quản lý chính sách (Policy Administration Point - PAP). Nó cung cấp một bộ API đầy đủ để quản lý vòng đời của các quy tắc policy trong hệ thống của bạn.

Các thay đổi được thực hiện thông qua `PolicyManager` sẽ được tự động lưu vào database nếu bạn đang sử dụng một Casbin Adapter hỗ trợ Auto-Save (như `gorm-adapter`).

## Tham khảo các phương thức

### Thêm Policy
* **`AddPolicy(rule []string) (bool, error)`**
    * Thêm một quy tắc mới.
    * Ví dụ: `pm.AddPolicy([]string{"Subject.role == 'guest'", "allow"})`
* **`AddPolicies(rules [][]string) (bool, error)`**
    * Thêm nhiều quy tắc cùng lúc.

### Đọc Policy
* **`GetPolicies() [][]string`**
    * Lấy tất cả các quy tắc hiện có trong bộ nhớ.
* **`GetFilteredPolicies(fieldIndex int, fieldValues ...string) ([][]string, error)`**
    * Lấy các quy tắc được lọc. Ví dụ: `pm.GetFilteredPolicies(1, "allow")` để lấy tất cả các rule có `effect` là `allow`.
* **`HasPolicy(rule []string) bool`**
    * Kiểm tra một quy tắc đã tồn tại hay chưa.

### Cập nhật Policy
* **`UpdatePolicy(oldRule []string, newRule []string) (bool, error)`**
    * Thay thế một quy tắc cũ bằng một quy tắc mới.

### Xóa Policy
* **`RemovePolicy(rule []string) (bool, error)`**
    * Xóa một quy tắc cụ thể.
* **`RemovePolicies(rules [][]string) (bool, error)`**
    * Xóa nhiều quy tắc cùng lúc.
* **`ClearAllPolicies()`**
    * Xóa toàn bộ các quy tắc trong bộ nhớ (không ảnh hưởng đến DB trừ khi gọi `Save`).

### Đồng bộ hóa
* **`LoadPoliciesFromStorage() error`**
    * Xóa cache bộ nhớ và tải lại toàn bộ policy từ nguồn lưu trữ (DB/file). Rất quan trọng để đồng bộ hóa.
* **`SavePoliciesToStorage() error`**
    * Lưu trạng thái hiện tại của bộ nhớ xuống nguồn lưu trữ. Hữu ích khi bạn tắt Auto-Save trên adapter.