// file: go-abac-library/abac/interfaces.go
package abac

// Attributes là một kiểu map linh hoạt để chứa các thuộc tính (key-value).
type Attributes map[string]interface{}

// SubjectFetcher lấy thuộc tính của một chủ thể (người dùng).
type SubjectFetcher interface {
	GetSubjectAttributes(subjectID string) (Attributes, error)
}

// ResourceFetcher lấy thuộc tính của một tài nguyên.
type ResourceFetcher interface {
	GetResourceAttributes(resourceID string) (Attributes, error)
}
