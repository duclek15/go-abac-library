// file: internal/mocks/fetchers.go
package mocks

import "github.com/duclek15/go-abac-library/abac"

type MockFetcher struct{}

func (f *MockFetcher) GetSubjectAttributes(subjectID string) (abac.Attributes, error) {
	users := map[string]abac.Attributes{
		// User root toàn hệ thống
		"root_user": {"id": "root_user", "global_roles": []interface{}{"root"}},

		// User Tenant 1
		"t1_hr_manager": {
			"id": "t1_hr_manager",
			"tenants": []interface{}{
				map[string]interface{}{"id": "tenant1", "role": "hr_manager"},
			},
		},

		// User Tenant 2
		"t2_hr_manager": {
			"id": "t2_hr_manager",
			"tenants": []interface{}{
				map[string]interface{}{"id": "tenant2", "role": "hr_manager"},
			},
		},
		"ghost_user": nil, // User không tồn tại
	}

	if user, ok := users[subjectID]; ok {
		if user == nil {
			return nil, abac.ErrSubjectNotFound
		}
		return user, nil
	}
	return nil, abac.ErrSubjectNotFound
}

func (f *MockFetcher) GetResourceAttributes(resourceID string) (abac.Attributes, error) {
	requests := map[string]abac.Attributes{
		// Đơn từ của Tenant 1
		"t1_eng_request": {"id": "t1_eng_request", "tenant": "tenant1", "department": "engineering"},

		// Đơn từ của Tenant 2
		"t2_hr_request":    {"id": "t2_hr_request", "tenant": "tenant2", "department": "hr"},
		"t2_sales_request": {"id": "t2_sales_request", "tenant": "tenant2", "department": "sales"},
	}

	if req, ok := requests[resourceID]; ok {
		return req, nil
	}
	return nil, abac.ErrResourceNotFound
}
