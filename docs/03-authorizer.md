# 3. The Authorizer (PDP)

`Authorizer` là thành phần trung tâm chịu trách nhiệm đưa ra quyết định phân quyền (Policy Decision Point - PDP). Nhiệm vụ duy nhất của nó là trả lời câu hỏi: "Chủ thể này có được phép thực hiện hành động này trên tài nguyên này không?"

## Phương thức `Check()`

Đây là phương thức cốt lõi bạn sẽ sử dụng.

**Chữ ký hàm:**
```go
func (a *Authorizer) Check(subjectID, resourceID, action string) (bool, error)
```

**Tham số:**
* `subjectID (string)`: ID duy nhất của chủ thể đang yêu cầu (ví dụ: ID người dùng, API key).
* `resourceID (string)`: ID duy nhất của tài nguyên bị tác động (ví dụ: ID tài liệu, ID đơn từ).
* `action (string)`: Hành động đang được thực hiện (ví dụ: `read`, `edit`, `approve_level_2`).

**Giá trị trả về:**
* `bool`: `true` nếu được phép, `false` nếu bị từ chối.
* `error`: `nil` nếu không có lỗi, hoặc trả về lỗi nếu không thể lấy thuộc tính hoặc có lỗi trong quá trình đánh giá.

## Ví dụ sử dụng trong Middleware (PEP)

Cách sử dụng phổ biến nhất của `Authorizer` là bên trong một middleware để bảo vệ các API endpoint.

```go
import "github.com/gin-gonic/gin"

// authMiddleware đóng vai trò là PEP
func (app *App) authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Lấy thông tin từ request
        subjectID := c.GetString("userID") // Lấy từ JWT token
        resourceID := "/requests/" + c.Param("id")
        action := "read"
        
        // Gọi PDP để xin quyết định
        isAllowed, err := app.Authorizer.Check(subjectID, resourceID, action)
        
        if err != nil || !isAllowed {
            // Nếu bị từ chối hoặc có lỗi, chặn request
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
            return
        }
        
        // Nếu được phép, cho request đi tiếp
        c.Next()
    }
}
```