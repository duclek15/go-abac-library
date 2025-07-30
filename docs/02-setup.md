# 2. Hướng dẫn Cài đặt & Thiết lập

Tài liệu này hướng dẫn cách cài đặt và các phương thức khởi tạo hệ thống ABAC trong dự án của bạn.

## Cài đặt

Bạn cần cài đặt thư viện chính và các dependency cần thiết.

```bash
# Thư viện chính
go get github.com/duclek15/go-abac-library/abac

# Thư viện đánh giá biểu thức (quan trọng)
go get github.com/casbin/govaluate

# Adapter cho GORM (nếu dùng DB)
go get github.com/casbin/gorm-adapter/v3

# GORM và driver DB (ví dụ: SQLite)
go get gorm.io/gorm
go get gorm.io/driver/sqlite
```

## Các phương thức khởi tạo

Thư viện cung cấp nhiều hàm khởi tạo (factory functions) khác nhau, mỗi hàm phục vụ cho một trường hợp sử dụng cụ thể.

---
### 1. NewABACSystemFromDB (Khuyến nghị cho Production)
* **Dùng khi nào?** Khi bạn cần quản lý policy một cách linh hoạt và bền vững trong cơ sở dữ liệu.
* **Khởi tạo:**
  ```go
  func NewABACSystemFromDB(modelPath string, db *gorm.DB, sf SubjectFetcher, rf ResourceFetcher) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  // Giả sử 'db' là con trỏ *gorm.DB đã được kết nối
  // và 'myFetcher' là PIP của bạn.
  
  // Tạo bảng 'casbin_rule' nếu nó chưa tồn tại
  db.AutoMigrate(&gormadapter.CasbinRule{})

  authorizer, policyManager, err := abac.NewABACSystemFromDB(
      "./path/to/model.conf",
      db,
      myFetcher,
      myFetcher,
  )
  ```

---
### 2. NewABACSystemFromFile
* **Dùng khi nào?** Cho các dự án đơn giản, script, hoặc khi policy ít khi thay đổi.
* **Khởi tạo:**
  ```go
  func NewABACSystemFromFile(modelPath, policyPath string, sf SubjectFetcher, rf ResourceFetcher) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  authorizer, policyManager, err := abac.NewABACSystemFromFile(
      "./path/to/model.conf",
      "./path/to/policy.csv",
      myFetcher,
      myFetcher,
  )
  ```

---
### 3. NewABACSystemFromStrings
* **Dùng khi nào?** Rất hữu ích cho unit test, hoặc khi bạn lấy model/policy từ một nguồn khác (server cấu hình, biến môi trường) dưới dạng chuỗi.
* **Khởi tạo:**
  ```go
  func NewABACSystemFromStrings(modelStr, policyStr string, sf SubjectFetcher, rf ResourceFetcher) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  modelStr := `
  [request_definition] 
  r = req
  [policy_definition]
  p = rule, eft
  [policy_effect]
  e = some(where (p.eft == allow))
  [matchers]
  m = evaluate(p.rule, r.req)`
  policyStr := `"p, \"Subject.role == 'admin'\", allow"`
  authorizer, policyManager, err := abac.NewABACSystemFromStrings(modelStr, policyStr, myFetcher, myFetcher,)
  ```
---
### 4. NewABACSystemFromDBUseTableName
* **Dùng khi nào?** Giống như `NewABACSystemFromDB`, nhưng khi bạn muốn tùy chỉnh tên bảng lưu trữ policy trong database (thay vì dùng tên mặc định `casbin_rule`).
* **Khởi tạo:**
  ```go
  func NewABACSystemFromDBUseTableName(modelPath string, db *gorm.DB, tableName string, sf SubjectFetcher, rf ResourceFetcher) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  // Định nghĩa struct để GORM biết tên bảng mới
  type MyPermissionRules struct {
      gormadapter.CasbinRule
  }
  func (MyPermissionRules) TableName() string {
      return "my_permission_rules"
  }
  // Tạo bảng với tên tùy chỉnh
  db.AutoMigrate(&MyPermissionRules{})

  // Khởi tạo hệ thống với tên bảng mới
  authorizer, policyManager, err := abac.NewABACSystemFromDBUseTableName(
      "./path/to/model.conf",
      db,
      "my_permission_rules", // Tên bảng tùy chỉnh
      myFetcher,
      myFetcher,
  )
  ```