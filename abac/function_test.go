package abac

import (
	"testing"
)

func TestHasFunc(t *testing.T) {
	res, err := HasFunc([]int{1, 2, 3}, 2)
	if err != nil || res != true {
		t.Errorf("hasFunc failed: %v, %v", res, err)
	}
	res, err = HasFunc([]string{"a", "b"}, "c")
	if err != nil || res != false {
		t.Errorf("hasFunc failed: %v, %v", res, err)
	}
}

func TestIntersectsFunc(t *testing.T) {
	res, err := IntersectsFunc([]int{1, 2, 3}, []int{3, 4})
	if err != nil || res != true {
		t.Errorf("intersectsFunc failed: %v, %v", res, err)
	}
	res, err = IntersectsFunc([]string{"a"}, []string{"b"})
	if err != nil || res != false {
		t.Errorf("intersectsFunc failed: %v, %v", res, err)
	}
}

func TestIsIpInCidrFunc(t *testing.T) {
	res, err := IsIpInCidrFunc("192.168.1.1", "192.168.1.0/24")
	if err != nil || res != true {
		t.Errorf("isIpInCidrFunc failed: %v, %v", res, err)
	}
	res, err = IsIpInCidrFunc("10.0.0.1", "192.168.1.0/24")
	if err != nil || res != false {
		t.Errorf("isIpInCidrFunc failed: %v, %v", res, err)
	}
}

func TestMatchesFunc(t *testing.T) {
	res, err := MatchesFunc("hello123", "hello[0-9]+")
	if err != nil || res != true {
		t.Errorf("matchesFunc failed: %v, %v", res, err)
	}
	res, err = MatchesFunc("abc", "^d.*")
	if err != nil || res != false {
		t.Errorf("matchesFunc failed: %v, %v", res, err)
	}
}

func TestIsBusinessHoursFunc(t *testing.T) {
	res, err := IsBusinessHoursFunc(10.0, 9.0, 17.0)
	if err != nil || res != true {
		t.Errorf("isBusinessHoursFunc failed: %v, %v", res, err)
	}
	res, err = IsBusinessHoursFunc(20.0, 9.0, 17.0)
	if err != nil || res != false {
		t.Errorf("isBusinessHoursFunc failed: %v, %v", res, err)
	}
}

func TestHasGlobalRoleFunc(t *testing.T) {
	subject := Attributes{
		"id":           "root_user",
		"global_roles": []interface{}{"root", "super_admin"},
	}

	// Should find role
	res, err := HasGlobalRoleFunc(subject, "root")
	if err != nil || res != true {
		t.Errorf("HasGlobalRoleFunc should find 'root': %v, %v", res, err)
	}

	// Should not find role
	res, err = HasGlobalRoleFunc(subject, "guest")
	if err != nil || res != false {
		t.Errorf("HasGlobalRoleFunc should not find 'guest': %v, %v", res, err)
	}

	// Subject without global_roles
	emptySubject := Attributes{"id": "user1"}
	res, err = HasGlobalRoleFunc(emptySubject, "root")
	if err != nil || res != false {
		t.Errorf("HasGlobalRoleFunc should return false for subject without global_roles: %v, %v", res, err)
	}
}

func TestHasTenantRoleFunc(t *testing.T) {
	subject := Attributes{
		"id": "t1_hr_manager",
		"tenants": []interface{}{
			map[string]interface{}{"id": "tenant1", "role": "hr_manager"},
			map[string]interface{}{"id": "tenant2", "role": "viewer"},
		},
	}

	// Should find role in correct tenant
	res, err := HasTenantRoleFunc(subject, "tenant1", "hr_manager")
	if err != nil || res != true {
		t.Errorf("HasTenantRoleFunc should find hr_manager in tenant1: %v, %v", res, err)
	}

	// Wrong role in tenant
	res, err = HasTenantRoleFunc(subject, "tenant1", "admin")
	if err != nil || res != false {
		t.Errorf("HasTenantRoleFunc should not find admin in tenant1: %v, %v", res, err)
	}

	// Wrong tenant
	res, err = HasTenantRoleFunc(subject, "tenant3", "hr_manager")
	if err != nil || res != false {
		t.Errorf("HasTenantRoleFunc should not find role in non-existent tenant: %v, %v", res, err)
	}
}

func TestHasOrgRoleFunc(t *testing.T) {
	subject := Attributes{
		"id": "staff_user",
		"tenants": []interface{}{
			map[string]interface{}{
				"id":   "tenant1",
				"role": "member",
				"organizations": []interface{}{
					map[string]interface{}{"id": "org_hr_1", "role": "TP"},
					map[string]interface{}{"id": "org_eng_1", "role": "NV"},
				},
			},
		},
	}

	// Should find role in correct org
	res, err := HasOrgRoleFunc(subject, "org_hr_1", "TP")
	if err != nil || res != true {
		t.Errorf("HasOrgRoleFunc should find TP in org_hr_1: %v, %v", res, err)
	}

	// Wrong role in org
	res, err = HasOrgRoleFunc(subject, "org_hr_1", "NV")
	if err != nil || res != false {
		t.Errorf("HasOrgRoleFunc should not find NV in org_hr_1: %v, %v", res, err)
	}

	// Non-existent org
	res, err = HasOrgRoleFunc(subject, "org_finance", "TP")
	if err != nil || res != false {
		t.Errorf("HasOrgRoleFunc should not find role in non-existent org: %v, %v", res, err)
	}
}
