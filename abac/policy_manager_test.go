package abac

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"testing"
)

func newTestPolicyManager(t *testing.T) *PolicyManager {
	m, err := model.NewModelFromString(`
[request_definition]
 r = sub, obj, act
[policy_definition]
 p = sub, obj, act
[policy_effect]
 e = some(where (p.eft == allow))
[matchers]
 m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatalf("failed to create model: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}
	return &PolicyManager{enforcer: e}
}

func TestPolicyManager_AddAndRemovePolicy(t *testing.T) {
	pm := newTestPolicyManager(t)
	ok, err := pm.AddPolicy([]string{"alice", "data1", "read"})
	if err != nil || !ok {
		t.Fatalf("AddPolicy failed: %v", err)
	}
	ok, err = pm.HasPolicy([]string{"alice", "data1", "read"})
	if err != nil || !ok {
		t.Fatalf("HasPolicy failed: %v", err)
	}
	ok, err = pm.RemovePolicy([]string{"alice", "data1", "read"})
	if err != nil || !ok {
		t.Fatalf("RemovePolicy failed: %v", err)
	}
}

func TestPolicyManager_UpdatePolicy(t *testing.T) {
	pm := newTestPolicyManager(t)
	pm.AddPolicy([]string{"bob", "data2", "write"})
	ok, err := pm.UpdatePolicy([]string{"bob", "data2", "write"}, []string{"bob", "data2", "read"})
	if err != nil || !ok {
		t.Fatalf("UpdatePolicy failed: %v", err)
	}
	ok, err = pm.HasPolicy([]string{"bob", "data2", "read"})
	if err != nil || !ok {
		t.Fatalf("HasPolicy after update failed: %v", err)
	}
}
