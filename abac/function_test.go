package abac

import (
	"testing"
)

func TestHasFunc(t *testing.T) {
	res, err := hasFunc([]int{1, 2, 3}, 2)
	if err != nil || res != true {
		t.Errorf("hasFunc failed: %v, %v", res, err)
	}
	res, err = hasFunc([]string{"a", "b"}, "c")
	if err != nil || res != false {
		t.Errorf("hasFunc failed: %v, %v", res, err)
	}
}

func TestIntersectsFunc(t *testing.T) {
	res, err := intersectsFunc([]int{1, 2, 3}, []int{3, 4})
	if err != nil || res != true {
		t.Errorf("intersectsFunc failed: %v, %v", res, err)
	}
	res, err = intersectsFunc([]string{"a"}, []string{"b"})
	if err != nil || res != false {
		t.Errorf("intersectsFunc failed: %v, %v", res, err)
	}
}

func TestIsIpInCidrFunc(t *testing.T) {
	res, err := isIpInCidrFunc("192.168.1.1", "192.168.1.0/24")
	if err != nil || res != true {
		t.Errorf("isIpInCidrFunc failed: %v, %v", res, err)
	}
	res, err = isIpInCidrFunc("10.0.0.1", "192.168.1.0/24")
	if err != nil || res != false {
		t.Errorf("isIpInCidrFunc failed: %v, %v", res, err)
	}
}

func TestMatchesFunc(t *testing.T) {
	res, err := matchesFunc("hello123", "hello[0-9]+")
	if err != nil || res != true {
		t.Errorf("matchesFunc failed: %v, %v", res, err)
	}
	res, err = matchesFunc("abc", "^d.*")
	if err != nil || res != false {
		t.Errorf("matchesFunc failed: %v, %v", res, err)
	}
}

func TestIsBusinessHoursFunc(t *testing.T) {
	res, err := isBusinessHoursFunc(10.0, 9.0, 17.0)
	if err != nil || res != true {
		t.Errorf("isBusinessHoursFunc failed: %v, %v", res, err)
	}
	res, err = isBusinessHoursFunc(20.0, 9.0, 17.0)
	if err != nil || res != false {
		t.Errorf("isBusinessHoursFunc failed: %v, %v", res, err)
	}
}
