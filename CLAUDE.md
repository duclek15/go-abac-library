# CLAUDE.md

Guidance for Claude Code when working with the go-abac-library (v1.0.17).

## Project Overview

A custom ABAC (Attribute-Based Access Control) library built in Go using Casbin as the core policy engine. Supports multi-tenancy, custom functions, batch resource checking, and decision tracing.

**Module:** `github.com/duclek15/go-abac-library`
**Current version:** v1.0.17

## Project Structure

```
abac/
├── authorizer.go       # Authorizer (PDP): Check(), CheckWithTrace(), factory functions, tracing infra
├── policy_manager.go   # PolicyManager (PAP): CRUD operations for policies
├── function.go         # 8 built-in custom functions
├── interfaces.go       # SubjectFetcher, ResourceFetcher, Attributes type
├── errors.go           # ErrSubjectNotFound, ErrResourceNotFound
├── *_test.go           # Unit tests
casbin_config/
├── abac_model.conf     # Multi-tenant Casbin model (r = tenant, req)
├── abac_policy.csv     # Example tenant-scoped policies
internal/mocks/         # Mock fetchers for testing
_examples/              # Usage examples
docs/                   # Documentation (6 chapters)
```

## Key API

### Authorizer (PDP)
```go
// Main check — returns allow/deny
func (a *Authorizer) Check(
    ctx *context.Context, tenantID string,
    subject interface{}, resource interface{},
    action string, envAttrs *Attributes,
) (bool, error)

// Check with decision tracing — returns allow/deny + trace
func (a *Authorizer) CheckWithTrace(
    ctx *context.Context, tenantID string,
    subject interface{}, resource interface{},
    action string, envAttrs *Attributes,
    opts ...TraceOption,
) (bool, *DecisionTrace, error)
```

### Fetcher Interfaces (PIP)
```go
type SubjectFetcher interface {
    GetSubjectAttributes(ctx *context.Context, subject interface{}) (Attributes, error)
}
type ResourceFetcher interface {
    GetResourceAttributes(ctx *context.Context, resource interface{}) ([]Attributes, error)
}
```

### Factory Functions
All accept `CustomFunctionMap` for registering domain-specific functions:
```go
NewABACSystemFromDB(modelPath, db, sf, rf, customFunc)       // Production (DB policies)
NewABACSystemFromFile(modelPath, policyPath, sf, rf, customFunc)  // Static policies
NewABACSystemFromStrings(modelStr, policyStr, sf, rf, customFunc) // Testing
NewABACSystemFromDBUseTableName(modelPath, db, prefix, tableName, sf, rf, customFunc) // Custom table
```

### Tracing Options
```go
WithPredicateTracing(true)   // Track custom function calls
WithAttributeTracing(true)   // Track attribute access
WithMaxItems(200)            // Limit trace items
WithRedactor(fn)             // Custom PII redaction
```

### DecisionTrace (returned by CheckWithTrace)
```go
type DecisionTrace struct {
    MatchedPolicies     []RuleMatch
    Predicates          []PredicateEvaluation
    AttributesEvaluated []AttributeAccess
    EvaluationMs        int64
    EngineVersion       string
    Error               string
}
```

### Built-in Functions (8)
| Function | Purpose |
|----------|---------|
| `has(list, value)` | Check value in list |
| `intersects(list1, list2)` | Check list intersection |
| `isIpInCidr(ip, cidr)` | IP range check |
| `matches(text, pattern)` | Regex matching |
| `isBusinessHours(time, start, end)` | Time-based access |
| `hasGlobalRole(Subject, role)` | Global system-wide role |
| `hasTenantRole(Subject, tenantID, role)` | Tenant-specific role |
| `hasOrgRole(Subject, orgID, role)` | Organization-specific role |

### CustomFunctionMap
```go
type CustomFunctionMap map[string]govaluate.ExpressionFunction
```
Register domain-specific functions callable from policy expressions.

## Policy Model (Multi-Tenant)
```
[request_definition]
r = tenant, req

[policy_definition]
p = tenant, rule, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (r.tenant == p.tenant || p.tenant == '*') && evaluate(p.rule, r.req)
```

## Common Commands
```bash
go test ./abac/...          # Run unit tests
go test -v ./abac/...       # Verbose
go build ./...              # Build
```

## Dependencies
- `github.com/casbin/casbin/v2` v2.110.0 — Policy engine
- `github.com/casbin/gorm-adapter/v3` v3.34.0 — DB persistence
- `github.com/casbin/govaluate` v1.8.0 — Expression evaluation
- `gorm.io/gorm` v1.30.0 — ORM

## Remaining Improvements
- **Caching**: No built-in caching for fetcher results or decisions — callers should implement in Fetcher or use decorator
- **Policy hot-reload**: `LoadPoliciesFromStorage()` exists but no automatic watcher
- See `docs/06-known-issues-and-roadmap.md` for full list
