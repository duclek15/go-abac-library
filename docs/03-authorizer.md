# 3. The Authorizer (PDP)

`Authorizer` là thành phần trung tâm chịu trách nhiệm đưa ra quyết định phân quyền (Policy Decision Point - PDP).

## Phương thức `Check()`

Phương thức chính để kiểm tra quyền truy cập.

**Chữ ký hàm:**
```go
func (a *Authorizer) Check(
    ctx *context.Context,
    tenantID string,
    subject interface{},
    resource interface{},
    action string,
    envAttrs *Attributes,
) (bool, error)
```

**Tham số:**
* `ctx (*context.Context)`: Context cho timeout, cancel, tracing.
* `tenantID (string)`: ID của tenant hiện tại (dùng cho multi-tenancy, policies scoped theo tenant).
* `subject (interface{})`: ID hoặc object của chủ thể — truyền vào `SubjectFetcher.GetSubjectAttributes()`.
* `resource (interface{})`: ID hoặc object của tài nguyên — truyền vào `ResourceFetcher.GetResourceAttributes()`.
* `action (string)`: Hành động đang được thực hiện (ví dụ: `read`, `edit`, `approve_level_2`).
* `envAttrs (*Attributes)`: Thuộc tính môi trường bổ sung (có thể `nil`).

**Giá trị trả về:**
* `bool`: `true` nếu được phép, `false` nếu bị từ chối.
* `error`: `nil` nếu không có lỗi.

**Batch resource checking:** `ResourceFetcher` trả về `[]Attributes`. `Check()` sẽ evaluate tất cả resources — chỉ allow nếu **tất cả** đều pass.

---

## Phương thức `CheckWithTrace()`

Giống `Check()` nhưng trả thêm `DecisionTrace` chứa lý do quyết định — hữu ích cho debugging và audit.

**Chữ ký hàm:**
```go
func (a *Authorizer) CheckWithTrace(
    ctx *context.Context,
    tenantID string,
    subject interface{},
    resource interface{},
    action string,
    envAttrs *Attributes,
    opts ...TraceOption,
) (bool, *DecisionTrace, error)
```

**Tham số bổ sung:**
* `opts (...TraceOption)`: Cấu hình tracing (xem bên dưới).

**DecisionTrace chứa:**
```go
type DecisionTrace struct {
    MatchedPolicies     []RuleMatch           // Policies nào matched/denied
    Predicates          []PredicateEvaluation // Custom functions đã gọi + kết quả
    AttributesEvaluated []AttributeAccess     // Attributes đã đọc
    EvaluationMs        int64                 // Thời gian evaluate (ms)
    EngineVersion       string                // Version thư viện
    Error               string                // Lỗi nếu có
}
```

**Trace Options:**
```go
// Bật tracking các custom function calls (mặc định: true)
abac.WithPredicateTracing(true)

// Bật tracking attribute access (mặc định: false)
abac.WithAttributeTracing(true)

// Giới hạn số items trong trace (mặc định: 200)
abac.WithMaxItems(100)

// Custom PII redaction function
abac.WithRedactor(func(scope, path string, raw interface{}) string {
    // mask sensitive values
    return fmt.Sprint(raw)
})
```

**Ví dụ:**
```go
allowed, trace, err := authorizer.CheckWithTrace(
    &ctx,
    organizationID,
    userID,
    resourceIDs,
    "edit",
    nil,
    abac.WithPredicateTracing(true),
    abac.WithAttributeTracing(true),
)

if !allowed {
    log.Printf("Denied. Matched policies: %+v", trace.MatchedPolicies)
    log.Printf("Predicates evaluated: %+v", trace.Predicates)
}
```

---

## Ví dụ sử dụng trong Middleware (PEP)

```go
import "github.com/gin-gonic/gin"

func (app *App) authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx := c.Request.Context()
        subjectID := c.GetString("userID")
        tenantID := c.GetString("tenantID")
        resourceID := c.Param("id")
        action := "read"

        isAllowed, err := app.Authorizer.Check(
            &ctx, tenantID, subjectID, resourceID, action, nil,
        )

        if err != nil || !isAllowed {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
            return
        }

        c.Next()
    }
}
```
