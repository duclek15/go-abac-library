# Thư viện Phân quyền ABAC bằng Go & Casbin

[![Go Report Card](https://goreportcard.com/badge/github.com/duclek15/go-abac-library)](https://goreportcard.com/report/github.com/duclek15/go-abac-library)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Một thư viện phân quyền dựa trên thuộc tính (Attribute-Based Access Control) mạnh mẽ, linh hoạt và dễ mở rộng được xây dựng bằng Go, sử dụng lõi Casbin. Thư viện này được thiết kế để tách biệt hoàn toàn logic phân quyền khỏi logic nghiệp vụ và nguồn dữ liệu của bạn.

## Tính năng nổi bật

* **Kiến trúc tách biệt:** Tuân thủ kiến trúc tiêu chuẩn (PDP, PIP, PAP), giúp code của bạn sạch sẽ và dễ bảo trì.
* **Multi-Tenancy:** Hỗ trợ phân quyền theo tenant với policy scoping và tenant inheritance.
* **Custom Functions:** Đăng ký domain-specific functions qua `CustomFunctionMap`, gọi trực tiếp từ policy expressions.
* **Decision Tracing:** `CheckWithTrace()` trả về lý do quyết định chi tiết cho audit và debugging.
* **Hỗ trợ Database:** Tích hợp PostgreSQL, MySQL,... thông qua Casbin GORM Adapter.
* **Policy động:** Quản lý policy (CRUD) qua `PolicyManager` mà không cần restart server.
* **8 hàm có sẵn:** has, intersects, isIpInCidr, matches, isBusinessHours, hasGlobalRole, hasTenantRole, hasOrgRole.

## Cài đặt

```bash
go get github.com/duclek15/go-abac-library/abac
```

## Bắt đầu nhanh (Quick Start)

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/duclek15/go-abac-library/abac"
)

// Triển khai Fetcher (PIP)
type MockFetcher struct{}

func (mf *MockFetcher) GetSubjectAttributes(ctx *context.Context, subject interface{}) (abac.Attributes, error) {
	subjectID := subject.(string)
	if subjectID == "alice" {
		return abac.Attributes{
			"id":           "alice",
			"global_roles": []interface{}{"admin"},
		}, nil
	}
	return abac.Attributes{"id": subjectID, "global_roles": []interface{}{"guest"}}, nil
}

func (mf *MockFetcher) GetResourceAttributes(ctx *context.Context, resource interface{}) ([]abac.Attributes, error) {
	return []abac.Attributes{{"id": resource}}, nil
}

func main() {
	modelStr := `
[request_definition]
r = tenant, req

[policy_definition]
p = tenant, rule, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (r.tenant == p.tenant || p.tenant == '*') && evaluate(p.rule, r.req)`

	policyStr := `
p, *, "hasGlobalRole(Subject, 'admin') && Action == 'write'", allow
p, *, "Action == 'read'", allow`

	// Đăng ký custom functions
	funcs := abac.CustomFunctionMap{
		"hasGlobalRole": abac.HasGlobalRoleFunc,
	}

	authorizer, _, err := abac.NewABACSystemFromStrings(
		modelStr, policyStr, &MockFetcher{}, &MockFetcher{}, funcs,
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// Admin có thể write
	canWrite, _ := authorizer.Check(&ctx, "*", "alice", "report", "write", nil)
	fmt.Printf("Can alice write? %v\n", canWrite) // true

	// Guest không thể write
	canWrite, _ = authorizer.Check(&ctx, "*", "bob", "report", "write", nil)
	fmt.Printf("Can bob write? %v\n", canWrite) // false

	// Ai cũng có thể read
	canRead, _ := authorizer.Check(&ctx, "*", "bob", "report", "read", nil)
	fmt.Printf("Can bob read? %v\n", canRead) // true
}
```

## Tài liệu đầy đủ

Để tìm hiểu sâu hơn về kiến trúc, cách thiết lập database và các tính năng nâng cao, vui lòng xem tài liệu đầy đủ tại thư mục `docs/`.

[**>> Đi đến Tài liệu đầy đủ <<**](docs/01-introduction.md)

## Giấy phép

Dự án này được cấp phép dưới Giấy phép MIT.
