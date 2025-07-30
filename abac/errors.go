// file: go-abac-library/abac/errors.go
package abac

import "errors"

var (
	// ErrSubjectNotFound được trả về khi không tìm thấy chủ thể.
	ErrSubjectNotFound = errors.New("subject not found")

	// ErrResourceNotFound được trả về khi không tìm thấy tài nguyên.
	ErrResourceNotFound = errors.New("resource not found")
)
