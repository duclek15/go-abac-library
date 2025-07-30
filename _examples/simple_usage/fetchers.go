// file: _examples/simple_usage/fetchers.go
package main

import (
	"fmt"
	"github.com/duc382/go-abac-library/abac"
)

// UserRepo là một PIP, triển khai SubjectFetcher.
type UserRepo struct{}

func (ur *UserRepo) GetSubjectAttributes(subjectID string) (abac.Attributes, error) {
	fmt.Printf("PIP: Fetching attributes for subject '%s'\n", subjectID)
	// Mock data người dùng trong môi trường multi-tenant
	users := map[string]abac.Attributes{
		// Tenant 1
		"t1_root":        {"id": "t1_root", "role": "root", "tenant": "tenant1"},
		"t1_hr_manager":  {"id": "t1_hr_manager", "role": "hr_manager", "department": "hr", "tenant": "tenant1"},
		"t1_eng_manager": {"id": "t1_eng_manager", "role": "manager", "department": "engineering", "tenant": "tenant1"},
		"t1_eng_staff":   {"id": "t1_eng_staff", "role": "staff", "department": "engineering", "tenant": "tenant1"},

		// Tenant 2
		"t2_root":        {"id": "t2_root", "role": "root", "tenant": "tenant2"},
		"t2_hr_manager":  {"id": "t2_hr_manager", "role": "hr_manager", "department": "hr", "tenant": "tenant2"},
		"t2_hr_staff":    {"id": "t2_hr_staff", "role": "staff", "department": "hr", "tenant": "tenant2"},
		"t2_sales_staff": {"id": "t2_sales_staff", "role": "staff", "department": "sales", "tenant": "tenant2"},
	}
	if user, ok := users[subjectID]; ok {
		return user, nil
	}
	return nil, abac.ErrSubjectNotFound
}

// DocumentRepo là một PIP, triển khai ResourceFetcher.
type DocumentRepo struct{}

func (dr *DocumentRepo) GetResourceAttributes(resourceID string) (abac.Attributes, error) {
	fmt.Printf("PIP: Fetching attributes for resource '%s'\n", resourceID)
	// Mock data tài nguyên (đơn từ)
	requests := map[string]abac.Attributes{
		// Đơn từ của Tenant 1
		"/requests/t1_eng_leave_001": {"id": "/requests/t1_eng_leave_001", "type": "leave_request", "department": "engineering", "tenant": "tenant1", "level": 2},

		// Đơn từ của Tenant 2
		"/requests/t2_hr_leave_001": {"id": "/requests/t2_hr_leave_001", "type": "leave_request", "department": "hr", "tenant": "tenant2", "level": 2},
		"/requests/t2_sales_ot_002": {"id": "/requests/t2_sales_ot_002", "type": "overtime_request", "department": "sales", "tenant": "tenant2", "level": 2},
	}
	if req, ok := requests[resourceID]; ok {
		return req, nil
	}
	return nil, abac.ErrResourceNotFound
}
