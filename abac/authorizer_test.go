// file: go-abac-library/abac/authorizer_test.go
package abac_test

import (
	"context"
	"testing"

	"github.com/duclek15/go-abac-library/abac"
	"github.com/duclek15/go-abac-library/internal/mocks"
	"github.com/stretchr/testify/assert"
)

func setupAuthorizer(t *testing.T) *abac.Authorizer {
	t.Helper()
	mockFetcher := &mocks.MockFetcher{}
	allFunctions := make(abac.CustomFunctionMap)
	allFunctions["has"] = abac.HasFunc
	allFunctions["intersects"] = abac.IntersectsFunc
	allFunctions["isIpInCidr"] = abac.IsIpInCidrFunc
	allFunctions["matches"] = abac.MatchesFunc
	allFunctions["isBusinessHours"] = abac.IsBusinessHoursFunc
	allFunctions["hasGlobalRole"] = abac.HasGlobalRoleFunc
	allFunctions["hasTenantRole"] = abac.HasTenantRoleFunc
	allFunctions["hasOrgRole"] = abac.HasOrgRoleFunc

	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf",
		"../casbin_config/abac_policy.csv",
		mockFetcher,
		mockFetcher,
		allFunctions,
	)
	assert.NoError(t, err, "Failed to create authorizer")
	return authorizer
}

func TestAuthorizer_MultiTenant(t *testing.T) {
	authorizer := setupAuthorizer(t)
	ctx := context.Background()

	testCases := []struct {
		name           string
		tenantID       string
		subjectID      string
		resourceID     string
		action         string
		expectedResult bool
		expectError    bool
	}{
		{
			name:           "[PASS] Root can approve any request in any tenant",
			tenantID:       "tenant2",
			subjectID:      "root_user",
			resourceID:     "t2_sales_request",
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
			tenantID:       "tenant2",
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
			expectError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasPermission, err := authorizer.Check(&ctx, tc.tenantID, tc.subjectID, tc.resourceID, tc.action, nil)

			if tc.expectError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error but got one")
			}

			assert.Equal(t, tc.expectedResult, hasPermission, "Permission result was not as expected")
		})
	}
}

func TestAuthorizer_CheckWithTrace_Allowed(t *testing.T) {
	authorizer := setupAuthorizer(t)
	ctx := context.Background()

	allowed, trace, err := authorizer.CheckWithTrace(
		&ctx, "tenant1", "t1_hr_manager", "t1_eng_request", "approve_level_2", nil,
		abac.WithPredicateTracing(true),
		abac.WithAttributeTracing(true),
	)

	assert.NoError(t, err)
	assert.True(t, allowed)
	assert.NotNil(t, trace)
	assert.Greater(t, trace.EvaluationMs+1, int64(0))
	assert.NotEmpty(t, trace.EngineVersion)
	assert.Empty(t, trace.Error)
}

func TestAuthorizer_CheckWithTrace_Denied(t *testing.T) {
	authorizer := setupAuthorizer(t)
	ctx := context.Background()

	allowed, trace, err := authorizer.CheckWithTrace(
		&ctx, "tenant2", "t2_hr_manager", "t2_sales_request", "approve_level_2", nil,
		abac.WithPredicateTracing(true),
	)

	assert.NoError(t, err)
	assert.False(t, allowed)
	assert.NotNil(t, trace)
}

func TestAuthorizer_CheckWithTrace_PredicateTracing(t *testing.T) {
	authorizer := setupAuthorizer(t)
	ctx := context.Background()

	_, trace, err := authorizer.CheckWithTrace(
		&ctx, "*", "root_user", "t1_eng_request", "approve_level_2", nil,
		abac.WithPredicateTracing(true),
	)

	assert.NoError(t, err)
	assert.NotNil(t, trace)
	assert.NotEmpty(t, trace.Predicates, "Predicates should be populated when tracing is enabled")
}

func TestAuthorizer_CheckWithTrace_AttributeTracing(t *testing.T) {
	authorizer := setupAuthorizer(t)
	ctx := context.Background()

	_, trace, err := authorizer.CheckWithTrace(
		&ctx, "tenant1", "t1_hr_manager", "t1_eng_request", "approve_level_2", nil,
		abac.WithAttributeTracing(true),
	)

	assert.NoError(t, err)
	assert.NotNil(t, trace)
	assert.NotEmpty(t, trace.AttributesEvaluated, "Attributes should be populated when attribute tracing is enabled")
}

func TestAuthorizer_CheckWithTrace_SubjectNotFound(t *testing.T) {
	authorizer := setupAuthorizer(t)
	ctx := context.Background()

	allowed, trace, err := authorizer.CheckWithTrace(
		&ctx, "tenant1", "ghost_user", "t1_eng_request", "approve_level_2", nil,
	)

	assert.Error(t, err)
	assert.False(t, allowed)
	assert.NotNil(t, trace)
	assert.NotEmpty(t, trace.Error)
}
