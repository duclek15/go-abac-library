// file: go-abac-library/abac/authorizer_test.go
package abac_test

import (
	"testing"

	"github.com/duclek15/go-abac-library/abac"
	"github.com/duclek15/go-abac-library/internal/mocks"
)

func TestAuthorizer(t *testing.T) {
	mockFetcher := &mocks.MockFetcher{}
	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf",
		"../casbin_config/abac_policy.csv",
		mockFetcher,
		mockFetcher,
	)
	if err != nil {
		t.Fatalf("Failed to create authorizer: %v", err)
	}

	testCases := []struct {
		name           string
		subjectID      string
		resourceID     string
		action         string
		envAtt         abac.Attributes
		expectedResult bool
		expectError    bool
	}{
		// Admin có thể làm mọi thứ (role == admin)
		{"Admin can do anything", "admin_user", "any_doc", "delete", abac.Attributes{}, true, false},
		// Editor chỉ được edit tài liệu cùng phòng ban
		{"Editor can edit their department's docs", "editor_user", "eng_doc", "edit", abac.Attributes{}, true, false},
		// Editor không được phép delete
		{"Editor cannot delete docs", "editor_user", "eng_doc", "delete", abac.Attributes{}, false, false},
		// Editor không được đọc tài liệu phòng ban khác
		{"User cannot access other departments' docs", "editor_user", "mkt_doc", "read", abac.Attributes{}, false, false},
		// User không tồn tại sẽ bị từ chối
		{"Non-existent user is denied", "ghost_user", "any_doc", "read", abac.Attributes{}, false, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasPermission, err := authorizer.Check(tc.subjectID, tc.resourceID, tc.action, tc.envAtt)
			if (err != nil) != tc.expectError {
				t.Errorf("Expected error: %v, got: %v", tc.expectError, err)
			}
			if hasPermission != tc.expectedResult {
				t.Errorf("Expected permission: %v, got: %v", tc.expectedResult, hasPermission)
			}
		})
	}
}
