# Changelog

All notable changes to the go-abac-library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v1.0.17] - 2026-03-16

### Added
- `CheckWithTrace()` method on `Authorizer` — returns `(bool, *DecisionTrace, error)` with full decision reasoning
- `DecisionTrace` struct with `MatchedPolicies`, `Predicates`, `AttributesEvaluated`, `EvaluationMs`, `EngineVersion`
- `TraceObserver` interface for custom trace collection
- Trace option functions: `WithPredicateTracing()`, `WithAttributeTracing()`, `WithMaxItems()`, `WithRedactor()`
- Built-in `traceCollector` that implements `TraceObserver`
- `AuthorizationRequest` now carries optional `Trace` and `TraceCfg` fields
- Predicate wrapping in `Evaluate()` — custom functions are automatically traced when tracing is enabled

## [v1.0.16] - 2026-03-16

### Changed
- Refactored factory function internals — `newSystemWithEnforcer()` now uses `expressionEvaluator` struct
- Removed `GetEnforcer()` method (was added in v1.0.5, removed for encapsulation)

### Fixed
- Safe type assertions in `Evaluate()` — uses comma-ok pattern instead of bare assertions

## [v1.0.13] - [v1.0.15]

### Changed
- Iterative refinements to factory function initialization
- `NewABACSystemFromDB()` and `NewABACSystemFromDBUseTableName()` now call `gormadapter.TurnOffAutoMigrate(db)` before creating adapter

## [v1.0.6] - [v1.0.12]

### Changed
- Factory functions updated to accept `CustomFunctionMap` parameter
- `expressionEvaluator` struct introduced to hold user-provided custom functions
- `Evaluate()` now merges built-in and user-provided functions before expression evaluation
- `SubjectFetcher` interface updated: `GetSubjectAttributes(ctx *context.Context, subject interface{}) (Attributes, error)`
- `ResourceFetcher` interface updated: `GetResourceAttributes(ctx *context.Context, resource interface{}) ([]Attributes, error)` — returns slice for batch resource checking
- `Check()` method signature updated to: `Check(ctx *context.Context, tenantID string, subject interface{}, resource interface{}, action string, envAttrsInput *Attributes) (bool, error)`
- Built-in functions expanded: added `HasGlobalRoleFunc`, `HasTenantRoleFunc`, `HasOrgRoleFunc`

## [v1.0.5] - [v1.0.4]

### Added
- `GetEnforcer()` method to access underlying Casbin enforcer (later removed in v1.0.16)

## [v1.0.3]

### Added
- Multi-tenancy support in `Check()` — added `tenantID` parameter
- Updated `abac_model.conf` to `r = tenant, req` with matcher `(r.tenant == p.tenant || p.tenant == '*')`
- Updated `abac_policy.csv` with tenant-scoped example policies
- `context.Context` support in `Check()` and Fetcher interfaces

### Changed
- `Check()` signature changed from `(subjectID, resourceID, action string, envAttrs Attributes)` to `(ctx, tenantID, subject, resource, action, envAttrs)`
- `ResourceFetcher.GetResourceAttributes()` now returns `[]Attributes` (slice) for batch checking

## [v1.0.2]

### Fixed
- Corrected Go module path

## [v1.0.1]

### Added
- Initial library structure with Casbin integration
- `Authorizer` (PDP) with `Check()` method
- `PolicyManager` (PAP) with full CRUD operations
- `SubjectFetcher` and `ResourceFetcher` interfaces (PIP)
- Built-in custom functions: `has`, `intersects`, `isIpInCidr`, `matches`, `isBusinessHours`
- Factory functions: `NewABACSystemFromFile`, `NewABACSystemFromDB`, `NewABACSystemFromStrings`, `NewABACSystemFromDBUseTableName`
- Default policy effect: deny-overrides-allow
- Documentation (5 chapters)
- Example usage with Gin middleware

## [v1.0.0]

### Added
- Initial project scaffold
