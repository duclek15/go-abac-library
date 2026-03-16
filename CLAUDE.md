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

## ABAC Evaluation Flow (Check internals)

```
Authorizer.Check(ctx, tenantID, subject, resource, action, envAttrs)
  │
  ├── 1. SubjectFetcher.GetSubjectAttributes(ctx, subject)
  │      → Returns Attributes (map[string]interface{})
  │      → Contains: organizations, roles, subordinate_units, job_titles, etc.
  │
  ├── 2. ResourceFetcher.GetResourceAttributes(ctx, resource)
  │      → Returns []Attributes (one per resource)
  │      → Contains: resource type, owner, metadata
  │
  ├── 3. Build request object (req):
  │      req = {Subject: subjectAttrs, Resource: resourceAttrs, Action: action, Env: envAttrs}
  │
  ├── 4. Casbin Enforce(tenantID, req)
  │      → Load policies matching tenant (or wildcard '*')
  │      → For each policy: evaluate(rule, req)
  │        → Expression engine (govaluate) evaluates rule string
  │        → Custom functions called during evaluation (hasOrgRole, etc.)
  │      → Apply policy effect: allow if any allow AND no deny
  │
  └── 5. Return (allowed bool, err error)

CheckWithTrace() adds:
  → DecisionTrace with: MatchedPolicies, Predicates, AttributesEvaluated, EvaluationMs
```

## How Backend Uses This Library

### Initialization (Wire DI)

```go
// backend_go/internal/wire/providers/abac.go
func ProvideABACSystem(db *gorm.DB, sf SubjectFetcher, rf ResourceFetcher) (*abac.Authorizer, *abac.PolicyManager) {
    customFuncs := abac.CustomFunctionMap{
        "hasOrgRole":                  HasOrgRoleFunc,
        "hasUnitRole":                 HasUnitRoleFunc,
        "hasUnitJobTitle":             HasUnitJobTitleFunc,
        "hasUnitJobLevel":             HasUnitJobLevelFunc,
        "hasUnitJobTitleAndJobLevel":  HasUnitJobTitleAndJobLevelFunc,
        "checkNestedSlice":            CheckNestedSliceFunc,
        "checkNestedObject":           CheckNestedObjectFunc,
        "matches":                     MatchesFunc,
    }
    authorizer, policyManager := abac.NewABACSystemFromDB(
        "config/abac_model.conf", db, sf, rf, customFuncs,
    )
    return authorizer, policyManager
}
```

### Subject Attributes Structure (passed to SubjectFetcher)

Backend's SubjectFetcher returns this structure via gRPC from subject-attribute-service:

```json
{
  "id": "user_uuid",
  "tenant_id": "tenant_uuid",
  "tenant_role": "admin",
  "organizations": [
    {
      "id": "org_uuid",
      "role": "org_admin",
      "staff_profile_id": "sp_uuid",
      "subordinate_units": [
        {
          "id": "unit_uuid",
          "role": "unit_manager",
          "job_title_id": "jt_uuid",
          "job_level_id": "jl_uuid"
        }
      ]
    }
  ]
}
```

Custom functions traverse this structure. Example: `hasOrgRole(Subject, 'org_uuid', 'org_admin')` iterates `Subject.organizations[]`, finds matching `id`, checks `role`.

### Permission Check UseCase

```go
// backend_go/internal/modules/authorization/application/queries/check_permission.go
func (uc *checkPermissionUseCase) Execute(ctx context.Context, input CheckPermissionInput) (bool, error) {
    allowed, trace, err := uc.abacAuthorizer.CheckWithTrace(
        &ctx, orgID, userID, input.Resources, input.Action, input.Env,
        abac.WithPredicateTracing(true),
        abac.WithAttributeTracing(true),
    )
    // Publish audit event to Kafka
    uc.publishAuditEvent(ctx, input, allowed, trace)
    return allowed, err
}
```

## Remaining Improvements
- **Caching**: No built-in caching for fetcher results or decisions — callers should implement in Fetcher or use decorator
- **Policy hot-reload**: `LoadPoliciesFromStorage()` exists but no automatic watcher
- See `docs/06-known-issues-and-roadmap.md` for full list
