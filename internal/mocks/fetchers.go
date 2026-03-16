// file: internal/mocks/fetchers.go
package mocks

import (
	"context"
	"github.com/duclek15/go-abac-library/abac"
)

type MockFetcher struct{}

func (f *MockFetcher) GetSubjectAttributes(ctx *context.Context, subject interface{}) (abac.Attributes, error) {
	subjectID, ok := subject.(string)
	if !ok {
		return nil, abac.ErrSubjectNotFound
	}

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
	}

	if user, ok := users[subjectID]; ok {
		return user, nil
	}
	return nil, abac.ErrSubjectNotFound
}

func (f *MockFetcher) GetResourceAttributes(ctx *context.Context, resource interface{}) ([]abac.Attributes, error) {
	resourceID, ok := resource.(string)
	if !ok {
		return nil, abac.ErrResourceNotFound
	}

	requests := map[string]abac.Attributes{
		// Đơn từ của Tenant 1
		"t1_eng_request": {"id": "t1_eng_request", "tenant": "tenant1", "department": "engineering"},

		// Đơn từ của Tenant 2
		"t2_hr_request":    {"id": "t2_hr_request", "tenant": "tenant2", "department": "hr"},
		"t2_sales_request": {"id": "t2_sales_request", "tenant": "tenant2", "department": "sales"},
	}

	if req, ok := requests[resourceID]; ok {
		return []abac.Attributes{req}, nil
	}
	return nil, abac.ErrResourceNotFound
}
