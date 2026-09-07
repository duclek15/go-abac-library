// file: go-abac-library/abac/corpus_functions_test.go
//
// Bản sao NGUYÊN VĂN (chỉ đổi package + đổi tên định danh Go cho khỏi đụng,
// không đổi logic) 6 hàm predicate thật của backend_go, lấy từ:
//
//	backend_go/internal/modules/authorization/domain/services/functions.go
//	(MatchesFunc, BelongsToResourceOrgFunc, HasAnyOrgRoleFunc,
//	 CheckNestedSliceFunc, HasAssignedRoleInResourceOrgFunc,
//	 HasAnyAssignedRoleFunc)
//
// Đây đúng bằng tập hàm mà 22 rule THẬT (dump từ bảng casbin_rule, DB dev
// netlab — xem testdata/rules_corpus.txt phần REAL) gọi tới. Copy thật để cả
// differential lẫn benchmark chạy trên đúng predicate production, KHÔNG PHẢI
// stub giả. go-abac-library không thể import backend_go làm dependency
// (chiều phụ thuộc module ngược — backend_go mới là bên import thư viện
// này), nên copy nguyên văn là cách duy nhất dùng được "predicate thật"
// trong bộ test của thư viện.
//
// Dùng chung cho MỌI test cần đánh giá corpus (differential, race, eviction,
// benchmark) — không tách riêng registry "chỉ built-in thư viện" nữa, vì
// phần lớn rule thật cần đúng 6 hàm này mới chạy được. Cơ chế loại rule gọi
// hàm chưa đăng ký (yêu cầu bắt buộc của phase) vẫn có thật trong
// expression_cache_test.go (filterExecutable) và được kiểm bằng một corpus
// TỔNG HỢP nhỏ ngay trong test (không qua file), vì với registry đầy đủ này
// không rule thật nào trong file bị loại — không có gì để minh hoạ nếu chỉ
// nhìn vào corpus thật.
package abac_test

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/duclek15/go-abac-library/abac"
)

// matchesFuncRegexCache lưu regex đã compile — bản sao logic cache của backend
// (đổi tên biến để không đụng identifier nào khác trong package abac_test).
var matchesFuncRegexCache sync.Map

// corpusMatchesFunc là bản sao nguyên văn MatchesFunc của backend.
func corpusMatchesFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'matches' yêu cầu 2 tham số")
	}
	text, ok1 := args[0].(string)
	pattern, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("tham số của 'matches' phải là chuỗi")
	}
	if cached, ok := matchesFuncRegexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp).MatchString(text), nil
	}
	if len(pattern) > 4096 {
		return false, fmt.Errorf("regex pattern quá dài (tối đa 4096 ký tự)")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("regex không hợp lệ: %w", err)
	}
	matchesFuncRegexCache.Store(pattern, re)
	return re.MatchString(text), nil
}

// corpusBelongsToResourceOrgFunc là bản sao nguyên văn BelongsToResourceOrgFunc.
func corpusBelongsToResourceOrgFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'belongsToResourceOrg' yêu cầu 2 tham số: Subject, Resource")
	}
	subject, ok1 := args[0].(abac.Attributes)
	resource, ok2 := args[1].(abac.Attributes)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("tham số của 'belongsToResourceOrg' phải là (Attributes, Attributes)")
	}
	resourceOrgIDs := make(map[string]bool)
	if resOrgs, ok := resource["organizations"].([]interface{}); ok {
		for _, org := range resOrgs {
			if orgMap, ok := org.(map[string]interface{}); ok {
				if id, _ := orgMap["id"].(string); id != "" {
					resourceOrgIDs[id] = true
				}
			}
		}
	}
	if len(resourceOrgIDs) == 0 {
		return false, nil
	}
	if subOrgs, ok := subject["organizations"].([]interface{}); ok {
		for _, org := range subOrgs {
			if orgMap, ok := org.(map[string]interface{}); ok {
				if id, _ := orgMap["id"].(string); resourceOrgIDs[id] {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// corpusHasAnyOrgRoleFunc là bản sao nguyên văn HasAnyOrgRoleFunc.
func corpusHasAnyOrgRoleFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'hasAnyOrgRole' yêu cầu 2 tham số: Subject, role")
	}
	subject, ok1 := args[0].(abac.Attributes)
	roleToCheck, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("tham số của 'hasAnyOrgRole' phải là (Attributes, string)")
	}
	if orgs, ok := subject["organizations"].([]interface{}); ok {
		for _, org := range orgs {
			if orgMap, ok := org.(map[string]interface{}); ok {
				if role, _ := orgMap["role"].(string); role == roleToCheck {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// corpusCheckNestedSliceFunc là bản sao nguyên văn CheckNestedSliceFunc.
func corpusCheckNestedSliceFunc(args ...interface{}) (interface{}, error) {
	if len(args) < 4 || (len(args)-2)%2 != 0 {
		return false, fmt.Errorf("hàm 'checkNestedSlice' yêu cầu: subject, path (string), key, value [, key, value...]")
	}
	subject := args[0]
	pathStr, ok := args[1].(string)
	if !ok {
		return false, fmt.Errorf("tham số thứ 2 phải là string path")
	}
	conditions := map[string]string{}
	for i := 2; i < len(args); i += 2 {
		key, okKey := args[i].(string)
		val, okVal := args[i+1].(string)
		if !okKey || !okVal {
			return false, fmt.Errorf("cặp key-value tại vị trí %d-%d phải là string", i, i+1)
		}
		conditions[key] = val
	}
	path := strings.Split(pathStr, ".")
	current := []interface{}{subject}
	for _, key := range path {
		next := []interface{}{}
		for _, c := range current {
			switch node := c.(type) {
			case map[string]interface{}:
				if child, exists := node[key]; exists {
					switch val := child.(type) {
					case []interface{}:
						next = append(next, val...)
					case map[string]interface{}:
						next = append(next, val)
					default:
						next = append(next, val)
					}
				}
			case abac.Attributes:
				if child, exists := node[key]; exists {
					switch val := child.(type) {
					case []interface{}:
						next = append(next, val...)
					case map[string]interface{}:
						next = append(next, val)
					default:
						next = append(next, val)
					}
				}
			}
		}
		current = next
	}
	for _, e := range current {
		switch val := e.(type) {
		case map[string]interface{}:
			match := true
			for k, v := range conditions {
				if fmt.Sprint(val[k]) != v {
					match = false
					break
				}
			}
			if match {
				return true, nil
			}
		default:
			if len(path) > 0 {
				lastKey := path[len(path)-1]
				if condVal, exists := conditions[lastKey]; exists && fmt.Sprint(val) == condVal {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// corpusHasAssignedRoleInResourceOrgFunc là bản sao nguyên văn
// HasAssignedRoleInResourceOrgFunc.
func corpusHasAssignedRoleInResourceOrgFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 3 {
		return false, fmt.Errorf("hàm 'hasAssignedRoleInResourceOrg' yêu cầu 3 tham số: Subject, Resource, role")
	}
	subject, ok1 := args[0].(abac.Attributes)
	resource, ok2 := args[1].(abac.Attributes)
	roleToCheck, ok3 := args[2].(string)
	if !ok1 || !ok2 || !ok3 {
		return false, fmt.Errorf("tham số của 'hasAssignedRoleInResourceOrg' phải là (Attributes, Attributes, string)")
	}
	resourceOrgIDs := make(map[string]bool)
	if resOrgs, ok := resource["organizations"].([]interface{}); ok {
		for _, org := range resOrgs {
			if orgMap, ok := org.(map[string]interface{}); ok {
				if id, _ := orgMap["id"].(string); id != "" {
					resourceOrgIDs[id] = true
				}
			}
		}
	}
	if len(resourceOrgIDs) == 0 {
		return false, nil
	}
	if subOrgs, ok := subject["organizations"].([]interface{}); ok {
		for _, org := range subOrgs {
			if orgMap, ok := org.(map[string]interface{}); ok {
				id, _ := orgMap["id"].(string)
				if !resourceOrgIDs[id] {
					continue
				}
				if assigned, ok := orgMap["assigned_roles"].([]interface{}); ok {
					for _, r := range assigned {
						if role, _ := r.(string); role == roleToCheck {
							return true, nil
						}
					}
				}
			}
		}
	}
	return false, nil
}

// corpusHasAnyAssignedRoleFunc là bản sao nguyên văn HasAnyAssignedRoleFunc.
func corpusHasAnyAssignedRoleFunc(args ...interface{}) (interface{}, error) {
	if len(args) != 2 {
		return false, fmt.Errorf("hàm 'hasAnyAssignedRole' yêu cầu 2 tham số: Subject, role")
	}
	subject, ok1 := args[0].(abac.Attributes)
	roleToCheck, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return false, fmt.Errorf("tham số của 'hasAnyAssignedRole' phải là (Attributes, string)")
	}
	if orgs, ok := subject["organizations"].([]interface{}); ok {
		for _, org := range orgs {
			if orgMap, ok := org.(map[string]interface{}); ok {
				if assigned, ok := orgMap["assigned_roles"].([]interface{}); ok {
					for _, r := range assigned {
						if role, _ := r.(string); role == roleToCheck {
							return true, nil
						}
					}
				}
			}
		}
	}
	return false, nil
}

// backendRealFunctions trả về 6 hàm predicate thật copy từ backend, đăng ký
// đúng tên mà rule text trong corpus (cả REAL lẫn SELF-AUTHORED "kiểu
// backend") dùng.
func backendRealFunctions() abac.CustomFunctionMap {
	return abac.CustomFunctionMap{
		"matches":                      corpusMatchesFunc,
		"belongsToResourceOrg":         corpusBelongsToResourceOrgFunc,
		"hasAnyOrgRole":                corpusHasAnyOrgRoleFunc,
		"checkNestedSliceFunc":         corpusCheckNestedSliceFunc,
		"hasAssignedRoleInResourceOrg": corpusHasAssignedRoleInResourceOrgFunc,
		"hasAnyAssignedRole":           corpusHasAnyAssignedRoleFunc,
	}
}
