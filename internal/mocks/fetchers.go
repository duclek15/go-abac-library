// file: go-abac-library/internal/mocks/fetchers.go
package mocks

import "github.com/duclek15/go-abac-library/abac"

// MockFetcher giả lập việc lấy dữ liệu cho unit test.
type MockFetcher struct{}

func (mf *MockFetcher) GetSubjectAttributes(subjectID string) (abac.Attributes, error) {
	switch subjectID {
	case "admin_user":
		return abac.Attributes{"role": "admin", "department": "it"}, nil
	case "editor_user":
		return abac.Attributes{"role": "editor", "department": "engineering"}, nil
	default:
		return nil, abac.ErrSubjectNotFound
	}
}

func (mf *MockFetcher) GetResourceAttributes(resourceID string) (abac.Attributes, error) {
	switch resourceID {
	case "eng_doc":
		return abac.Attributes{"department": "engineering"}, nil
	case "mkt_doc":
		return abac.Attributes{"department": "marketing"}, nil
	default:
		return abac.Attributes{"department": "unknown"}, nil
	}
}
