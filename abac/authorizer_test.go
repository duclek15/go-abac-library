// file: go-abac-library/abac/authorizer_test.go
package abac_test

import (
	"testing"

	"github.com/duclek15/go-abac-library/abac"
	"github.com/duclek15/go-abac-library/internal/mocks"
	"github.com/stretchr/testify/assert"
)

func TestAuthorizer_MultiTenant(t *testing.T) {
	// --- Setup ---
	mockFetcher := &mocks.MockFetcher{}
	// 1. Thêm các hàm mặc định của thư viện
	allFunctions := make(abac.CustomFunctionMap)
	allFunctions["has"] = abac.HasFunc
	allFunctions["intersects"] = abac.IntersectsFunc
	allFunctions["isIpInCidr"] = abac.IsIpInCidrFunc
	allFunctions["matches"] = abac.MatchesFunc
	allFunctions["isBusinessHours"] = abac.IsBusinessHoursFunc
	allFunctions["hasGlobalRole"] = abac.HasGlobalRoleFunc
	allFunctions["hasTenantRole"] = abac.HasTenantRoleFunc
	allFunctions["hasOrgRole"] = abac.HasOrgRoleFunc
	// Sử dụng NewABACSystemFromFile để nạp model và policy đã chuẩn bị
	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf",
		"../casbin_config/abac_policy.csv",
		mockFetcher,
		mockFetcher,
		allFunctions,
	)
	assert.NoError(t, err, "Failed to create authorizer")

	// --- Định nghĩa các ca kiểm thử ---
	testCases := []struct {
		name           string
		tenantID       string
		subjectID      string
		resourceID     string
		action         string
		expectedResult bool // Kết quả mong đợi (true: pass, false: deny)
		expectError    bool // Mong đợi có lỗi xảy ra hay không
	}{
		{
			name:           "[PASS] Root can approve any request in any tenant",
			tenantID:       "tenant2",
			subjectID:      "root_user",
			resourceID:     "t2_sales_request", // Duyệt đơn sales mà bình thường T2 HR Manager không được
			action:         "approve_level_2",
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "[PASS] T1 HR Manager can approve request from Engineering dept in T1",
			tenantID:       "tenant1",
			subjectID:      "t1_hr_manager",
			resourceID:     "t1_eng_request",
			action:         "approve_level_2",
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "[PASS] T2 HR Manager can approve request from HR dept in T2",
			tenantID:       "tenant2",
			subjectID:      "t2_hr_manager",
			resourceID:     "t2_hr_request",
			action:         "approve_level_2",
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "[FAIL] T2 HR Manager CANNOT approve request from Sales dept in T2",
			tenantID:       "tenant2",
			subjectID:      "t2_hr_manager",
			resourceID:     "t2_sales_request",
			action:         "approve_level_2",
			expectedResult: false,
			expectError:    false,
		},
		{
			name:           "[FAIL] T1 HR Manager CANNOT approve request from T2 (wrong tenant)",
			tenantID:       "tenant2", // Thử truy cập vào tenant2
			subjectID:      "t1_hr_manager",
			resourceID:     "t2_hr_request",
			action:         "approve_level_2",
			expectedResult: false,
			expectError:    false,
		},
		{
			name:           "[FAIL] Non-existent user is denied and returns error",
			tenantID:       "tenant1",
			subjectID:      "ghost_user",
			resourceID:     "t1_eng_request",
			action:         "approve_level_2",
			expectedResult: false,
			expectError:    true, // Mong đợi lỗi từ Fetcher
		},
	}

	// --- Chạy test ---
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasPermission, err := authorizer.Check(tc.tenantID, tc.subjectID, tc.resourceID, tc.action, nil)

			if tc.expectError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error but got one")
			}

			assert.Equal(t, tc.expectedResult, hasPermission, "Permission result was not as expected")
		})
	}
}
