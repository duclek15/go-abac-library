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