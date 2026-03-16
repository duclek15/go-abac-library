# 2. Hướng dẫn Cài đặt & Thiết lập

Tài liệu này hướng dẫn cách cài đặt và các phương thức khởi tạo hệ thống ABAC trong dự án của bạn.

## Cài đặt

```bash
go get github.com/duclek15/go-abac-library/abac
```

## CustomFunctionMap

Tất cả factory functions đều nhận tham số `CustomFunctionMap` để đăng ký các hàm tùy chỉnh domain-specific, có thể gọi trực tiếp từ policy expressions:

```go
type CustomFunctionMap map[string]govaluate.ExpressionFunction
```

Ví dụ:
```go
customFuncs := abac.CustomFunctionMap{
    "hasOrgRole":  myDomain.HasOrgRoleFunc,
    "hasUnitRole": myDomain.HasUnitRoleFunc,
}
```

## Fetcher Interfaces

Bạn cần triển khai 2 interfaces để cung cấp attributes:

```go
type SubjectFetcher interface {
    GetSubjectAttributes(ctx *context.Context, subject interface{}) (Attributes, error)
}

type ResourceFetcher interface {
    GetResourceAttributes(ctx *context.Context, resource interface{}) ([]Attributes, error)
}
```

**Lưu ý:**
- `ctx` là `*context.Context` (pointer) — cho phép truyền timeout, tracing, cancel
- `subject`/`resource` là `interface{}` — linh hoạt, thường truyền string ID
- `ResourceFetcher` trả về `[]Attributes` (slice) — hỗ trợ batch resource checking

## Các phương thức khởi tạo

---
### 1. NewABACSystemFromDB (Khuyến nghị cho Production)
* **Dùng khi nào?** Khi bạn cần quản lý policy một cách linh hoạt và bền vững trong cơ sở dữ liệu.
* **Khởi tạo:**
  ```go
  func NewABACSystemFromDB(
      modelPath string,
      db *gorm.DB,
      sf SubjectFetcher,
      rf ResourceFetcher,
      customFunc CustomFunctionMap,
  ) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  authorizer, policyManager, err := abac.NewABACSystemFromDB(
      "./config/abac_model.conf",
      db,
      mySubjectFetcher,
      myResourceFetcher,
      customFuncs, // hoặc nil nếu không cần custom functions
  )
  ```

---
### 2. NewABACSystemFromFile
* **Dùng khi nào?** Cho các dự án đơn giản, script, hoặc khi policy ít khi thay đổi.
* **Khởi tạo:**
  ```go
  func NewABACSystemFromFile(
      modelPath, policyPath string,
      sf SubjectFetcher,
      rf ResourceFetcher,
      customFunc CustomFunctionMap,
  ) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  authorizer, policyManager, err := abac.NewABACSystemFromFile(
      "./config/abac_model.conf",
      "./config/abac_policy.csv",
      mySubjectFetcher,
      myResourceFetcher,
      nil,
  )
  ```

---
### 3. NewABACSystemFromStrings
* **Dùng khi nào?** Rất hữu ích cho unit test, hoặc khi bạn lấy model/policy từ một nguồn khác dưới dạng chuỗi.
* **Khởi tạo:**
  ```go
  func NewABACSystemFromStrings(
      modelStr, policyStr string,
      sf SubjectFetcher,
      rf ResourceFetcher,
      customFunc CustomFunctionMap,
  ) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  modelStr := `
  [request_definition]
  r = tenant, req
  [policy_definition]
  p = tenant, rule, eft
  [policy_effect]
  e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
  [matchers]
  m = (r.tenant == p.tenant || p.tenant == '*') && evaluate(p.rule, r.req)`

  policyStr := `p, *, "Action == 'read'", allow`

  authorizer, _, err := abac.NewABACSystemFromStrings(
      modelStr, policyStr,
      &MockFetcher{}, &MockFetcher{},
      nil,
  )
  ```

---
### 4. NewABACSystemFromDBUseTableName
* **Dùng khi nào?** Giống `NewABACSystemFromDB`, nhưng khi bạn muốn tùy chỉnh tên bảng lưu trữ policy.
* **Khởi tạo:**
  ```go
  func NewABACSystemFromDBUseTableName(
      modelPath string,
      db *gorm.DB,
      prefix string,
      tableName string,
      sf SubjectFetcher,
      rf ResourceFetcher,
      customFunc CustomFunctionMap,
  ) (*Authorizer, *PolicyManager, error)
  ```
* **Ví dụ:**
  ```go
  authorizer, policyManager, err := abac.NewABACSystemFromDBUseTableName(
      "./config/abac_model.conf",
      db,
      "",                    // prefix
      "my_permission_rules", // tên bảng tùy chỉnh
      mySubjectFetcher,
      myResourceFetcher,
      customFuncs,
  )
  ```
