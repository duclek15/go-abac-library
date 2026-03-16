# 6. Vấn đề đã biết & Lộ trình phát triển

Tài liệu này ghi nhận trạng thái các vấn đề đã biết và lộ trình phát triển (cập nhật 2026-03).

## Trạng thái hiện tại: v1.0.17

Thư viện đã production-ready với đầy đủ features cho multi-tenant ABAC.

---

## Vấn đề đã giải quyết (Resolved)

| # | Vấn đề | Giải quyết ở version |
|---|--------|---------------------|
| 1 | Thiếu `context.Context` trong Fetcher interfaces | v1.0.3 — `*context.Context` param |
| 2 | Không hỗ trợ custom functions từ bên ngoài | v1.0.6+ — `CustomFunctionMap` param |
| 3 | Thiếu `CheckWithTrace()` / tracing | v1.0.17 — `CheckWithTrace()` + `DecisionTrace` |
| 4 | Chỉ check 1 resource | v1.0.3 — `ResourceFetcher` trả `[]Attributes` |
| 5 | Thiếu tenant/organization awareness | v1.0.3 — `tenantID` param trong `Check()` |
| 6 | Unsafe type assertions trong evaluate | v1.0.16 — comma-ok pattern |
| 7 | Không có functional options | v1.0.17 — `TraceOption` interface |

---

## Vấn đề còn tồn tại

### 1. Không có caching layer

**Mức độ:** Nên có (P2)

`Check()` và `CheckWithTrace()` gọi `SubjectFetcher` + `ResourceFetcher` trên **mọi request**. Không có built-in cache cho attributes hay decisions.

**Workaround hiện tại:** Caller tự implement caching trong Fetcher implementation hoặc dùng decorator pattern.

**Đề xuất cho tương lai:**
```go
// Option 1: Caching decorator
type CachedSubjectFetcher struct {
    inner SubjectFetcher
    cache *lru.Cache
    ttl   time.Duration
}

// Option 2: Built-in cache option
WithSubjectCache(ttl time.Duration)
```

### 2. Policy hot-reload

**Mức độ:** Nhẹ (P3)

`PolicyManager.LoadPoliciesFromStorage()` cho phép reload policies thủ công, nhưng không có watcher tự động reload khi DB thay đổi.

**Workaround:** Caller tự implement periodic reload hoặc event-driven reload.

### 3. `*context.Context` pointer pattern

**Mức độ:** Nhẹ (P3)

Fetcher interfaces dùng `*context.Context` (pointer) thay vì `context.Context` (value) theo Go convention. Không gây bug nhưng khác convention chuẩn.

### 4. Thiếu CHANGELOG trước v1.0.17

Các version v1.0.0 → v1.0.16 không có CHANGELOG chi tiết. File CHANGELOG.md mới tạo dựa trên git history, có thể thiếu chi tiết ở một số version giữa.

---

## Lộ trình đề xuất

| Phase | Hạng mục | Effort | Priority |
|-------|----------|--------|----------|
| Next | Thêm caching decorator/option | 3-4h | P2 |
| Next | Policy hot-reload watcher | 2-3h | P3 |
| Future | Chuẩn hóa `context.Context` (không pointer) | Breaking change | P3 |
| Future | Performance benchmarks | 2-3h | P3 |
