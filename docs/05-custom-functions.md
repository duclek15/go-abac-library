# 5. Viết Policy với Hàm tùy chỉnh

Hàm tùy chỉnh (Custom Functions) là tính năng mạnh mẽ nhất của thư viện này. Chúng cho phép bạn định nghĩa các logic phức tạp trong Go và gọi chúng trực tiếp từ các chuỗi policy, giúp các quy tắc của bạn trở nên cực kỳ biểu cảm và dễ đọc.

## Tham khảo các hàm có sẵn

Dưới đây là danh sách các hàm tùy chỉnh hữu ích được tích hợp sẵn.

### `has(list, value)`
* **Mô tả:** Kiểm tra xem một giá trị có tồn tại trong một danh sách (mảng) hay không.
* **Dùng khi:** Người dùng có nhiều vai trò, thuộc nhiều nhóm, hoặc một tài nguyên có nhiều nhãn.
* **Ví dụ Policy:**
    ```
    "has(Subject.roles, 'manager')"
    ```

### `intersects(list1, list2)`
* **Mô tả:** Kiểm tra xem hai danh sách có ít nhất một phần tử chung hay không.
* **Dùng khi:** Cần so khớp quyền giữa hai danh sách, ví dụ các phòng ban người dùng được phép truy cập và danh sách các phòng ban của tài liệu.
* **Ví dụ Policy:**
    ```
    "intersects(Subject.security_groups, Resource.required_groups)"
    ```

### `isIpInCidr(ip, cidr)`
* **Mô tả:** Kiểm tra một địa chỉ IP có nằm trong một dải mạng CIDR không.
* **Dùng khi:** Giới hạn quyền truy cập vào các tính năng nhạy cảm chỉ từ mạng nội bộ công ty.
* **Ví dụ Policy:**
    ```
    "has(Subject.roles, 'admin') && isIpInCidr(Env.ip_address, '10.0.0.0/8')"
    ```

### `matches(text, pattern)`
* **Mô tả:** So khớp một chuỗi với một mẫu biểu thức chính quy (Regex).
* **Dùng khi:** Cấp quyền trên các tài nguyên có cấu trúc đường dẫn hoặc tên định dạng, ví dụ: tất cả file trong một thư mục.
* **Ví dụ Policy:**
    ```
    "Action == 'read' && matches(Resource.path, '^/financials/q[1-4]-\d{4}\.pdf$')"
    ```

### `isBusinessHours(time, startHour, endHour)`
* **Mô tả:** Kiểm tra xem giờ hiện tại (0-23) có nằm trong khoảng giờ làm việc hay không.
* **Dùng khi:** Giới hạn các hành động quan trọng như chuyển tiền, xóa dữ liệu chỉ được thực hiện trong giờ hành chính.
* **Ví dụ Policy:**
    ```
    "Action == 'delete_database' && isBusinessHours(Env.timeOfDay, 9, 17)"
    ```

---

## Hàm phân quyền theo cấp bậc tổ chức

Các hàm dưới đây kiểm tra vai trò của Subject trong cấu trúc tổ chức phân cấp (global → tenant → organization).

### `hasGlobalRole(Subject, role)`
* **Mô tả:** Kiểm tra vai trò toàn hệ thống (system-wide). Duyệt `Subject.global_roles[]`.
* **Dùng khi:** Quyền áp dụng cho toàn bộ hệ thống, không phụ thuộc tenant hay organization.
* **Subject attribute cần có:** `global_roles: ["root", "super_admin", ...]`
* **Ví dụ Policy:**
    ```
    "Action == 'approve_level_2' && hasGlobalRole(Subject, 'root')"
    ```

### `hasTenantRole(Subject, tenantID, role)`
* **Mô tả:** Kiểm tra vai trò trong một tenant cụ thể. Duyệt `Subject.tenants[].id` và `Subject.tenants[].role`.
* **Dùng khi:** Quyền chỉ áp dụng trong phạm vi một tenant.
* **Subject attribute cần có:**
    ```json
    {
      "tenants": [
        {"id": "tenant1", "role": "hr_manager", "organizations": [...]}
      ]
    }
    ```
* **Ví dụ Policy:**
    ```
    "Action == 'approve_level_2' && hasTenantRole(Subject, 'tenant1', 'hr_manager')"
    ```

### `hasOrgRole(Subject, orgID, role)`
* **Mô tả:** Kiểm tra vai trò trong một tổ chức (organization) cụ thể. Duyệt `Subject.tenants[].organizations[].id` và `.role`.
* **Dùng khi:** Quyền chỉ áp dụng trong phạm vi một đơn vị/phòng ban cụ thể.
* **Subject attribute cần có:**
    ```json
    {
      "tenants": [
        {
          "id": "tenant1",
          "organizations": [
            {"id": "org_hr_1", "role": "TP"}
          ]
        }
      ]
    }
    ```
* **Ví dụ Policy:**
    ```
    "Action == 'edit' && hasOrgRole(Subject, 'org_hr_1', 'TP')"
    ```

---

## Đăng ký hàm tùy chỉnh từ bên ngoài

Ngoài 8 hàm có sẵn, bạn có thể đăng ký thêm domain-specific functions qua `CustomFunctionMap` khi khởi tạo hệ thống:

```go
customFuncs := abac.CustomFunctionMap{
    "hasUnitRole": func(args ...interface{}) (interface{}, error) {
        // Logic kiểm tra role trong subordinate unit
        subject := args[0].(abac.Attributes)
        unitID := args[1].(string)
        role := args[2].(string)
        // ... traverse subject attributes
        return true, nil
    },
}

authorizer, _, err := abac.NewABACSystemFromDB(
    modelPath, db, sf, rf, customFuncs,
)
```

Sau đó dùng trong policy:
```
"hasUnitRole(Subject, 'unit_123', 'manager')"
```