# Thư viện Phân quyền ABAC bằng Go & Casbin

[![Go Report Card](https://goreportcard.com/badge/github.com/duclek15/go-abac-library)](https://goreportcard.com/report/github.com/duclek15/go-abac-library)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Một thư viện phân quyền dựa trên thuộc tính (Attribute-Based Access Control) mạnh mẽ, linh hoạt và dễ mở rộng được xây dựng bằng Go, sử dụng lõi Casbin. Thư viện này được thiết kế để tách biệt hoàn toàn logic phân quyền khỏi logic nghiệp vụ và nguồn dữ liệu của bạn.

## ✨ Tính năng nổi bật

* **Kiến trúc tách biệt:** Tuân thủ kiến trúc tiêu chuẩn (PDP, PIP, PAP), giúp code của bạn sạch sẽ và dễ bảo trì.
* **Hỗ trợ Database:** Dễ dàng tích hợp với các cơ sở dữ liệu (PostgreSQL, MySQL,...) thông qua Casbin Adapters.
* **Policy động:** Dễ dàng quản lý policy (thêm, xóa, sửa, tải lại) thông qua API mà không cần khởi động lại server.
* **Hàm tùy chỉnh mạnh mẽ:** Hỗ trợ viết các quy tắc nghiệp vụ phức tạp (nhiều vai trò, kiểm tra IP, giờ giấc...) ngay trong policy.
* **Hỗ trợ Multi-Tenancy:** Dễ dàng mở rộng để giải quyết các bài toán phân quyền phức tạp trong các ứng dụng SaaS.

## 🚀 Cài đặt

```bash
go get github.com/duclek15/go-abac-library/abac
```

## ⚡ Bắt đầu nhanh (Quick Start)

Dưới đây là một ví dụ đơn giản nhất để chạy thư viện với policy được đọc từ file.

```go
package main

import (
	"fmt"
	"log"
	
	"github.com/duclek15/go-abac-library/abac"
)

// Triển khai Fetcher đơn giản (PIP)
type MockFetcher struct{}
func (mf *MockFetcher) GetSubjectAttributes(id string) (abac.Attributes, error) {
	if id == "alice" {
		return abac.Attributes{"role": "admin"}, nil
	}
	return abac.Attributes{"role": "guest"}, nil
}
func (mf *MockFetcher) GetResourceAttributes(id string) (abac.Attributes, error) {
	return abac.Attributes{}, nil
}

func main() {
    // Chuẩn bị model và policy dưới dạng chuỗi
	modelStr :=  `
        [request_definition]
        r = sub, obj, act

        [policy_definition]
        p = sub, obj, act

        [policy_effect]
        e = some(where (p.eft == allow))

        [matchers]
        m = r.sub.role == p.sub && r.act == p.act
        `
	policyStr := `
        p, admin, any, write
        p, guest, any, read
        `
    // Khởi tạo hệ thống
	authorizer, _, err := abac.NewABACSystemFromStrings(modelStr, policyStr, &MockFetcher{}, &MockFetcher{})
	if err != nil {
		log.Fatal(err)
	}

    // Kiểm tra quyền
	canWrite, _ := authorizer.Check("alice", "report", "write")
	fmt.Printf("Can alice write? %v\n", canWrite) // Kết quả: true

	canWriteAsGuest, _ := authorizer.Check("bob", "report", "write")
	fmt.Printf("Can bob write? %v\n", canWriteAsGuest) // Kết quả: false
}
```

## 📚 Tài liệu đầy đủ

Để tìm hiểu sâu hơn về kiến trúc, cách thiết lập database và các tính năng nâng cao, vui lòng xem tài liệu đầy đủ tại thư mục `docs/`.

[**>> Đi đến Tài liệu đầy đủ <<**](docs/01-introduction.md)

## 📄 Giấy phép

Dự án này được cấp phép dưới Giấy phép MIT.