// file: go-abac-library/abac/authorizer_checkmany_test.go
package abac_test

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/duclek15/go-abac-library/abac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== Fetcher đếm dùng riêng cho bộ test CheckMany =====
//
// Không tái dùng internal/mocks.MockFetcher (dữ liệu cố định, không đếm số
// lần gọi) hay corpusFetcher (không đếm) — bộ test này cần đếm số lần
// GetSubjectAttributes/GetResourceAttributes để chứng minh CheckMany chỉ
// fetch một lần bất kể số action.

type checkManySubject struct {
	attrs abac.Attributes
	err   error
}

type checkManyResource struct {
	attrs []abac.Attributes
	err   error
}

type countingFetcher struct {
	mu   sync.Mutex
	subj map[string]checkManySubject
	res  map[string]checkManyResource

	subjectCalls  int
	resourceCalls int
}

func newCountingFetcher() *countingFetcher {
	return &countingFetcher{
		subj: make(map[string]checkManySubject),
		res:  make(map[string]checkManyResource),
	}
}

func (f *countingFetcher) withSubject(id string, attrs abac.Attributes) *countingFetcher {
	f.subj[id] = checkManySubject{attrs: attrs}
	return f
}

func (f *countingFetcher) withSubjectError(id string, err error) *countingFetcher {
	f.subj[id] = checkManySubject{err: err}
	return f
}

func (f *countingFetcher) withResource(id string, attrs []abac.Attributes) *countingFetcher {
	f.res[id] = checkManyResource{attrs: attrs}
	return f
}

func (f *countingFetcher) withResourceError(id string, err error) *countingFetcher {
	f.res[id] = checkManyResource{err: err}
	return f
}

func (f *countingFetcher) resetCounts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subjectCalls = 0
	f.resourceCalls = 0
}

func (f *countingFetcher) counts() (subjectCalls, resourceCalls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subjectCalls, f.resourceCalls
}

func (f *countingFetcher) GetSubjectAttributes(_ *context.Context, subject interface{}) (abac.Attributes, error) {
	f.mu.Lock()
	f.subjectCalls++
	f.mu.Unlock()

	id, ok := subject.(string)
	if !ok {
		return nil, abac.ErrSubjectNotFound
	}
	entry, ok := f.subj[id]
	if !ok {
		return nil, abac.ErrSubjectNotFound
	}
	if entry.err != nil {
		return nil, entry.err
	}
	return entry.attrs, nil
}

func (f *countingFetcher) GetResourceAttributes(_ *context.Context, resource interface{}) ([]abac.Attributes, error) {
	f.mu.Lock()
	f.resourceCalls++
	f.mu.Unlock()

	id, ok := resource.(string)
	if !ok {
		return nil, abac.ErrResourceNotFound
	}
	entry, ok := f.res[id]
	if !ok {
		return nil, abac.ErrResourceNotFound
	}
	if entry.err != nil {
		return nil, entry.err
	}
	return entry.attrs, nil
}

// ===== Policy dùng riêng cho bộ test CheckMany =====
//
// Ghi CSV qua encoding/csv (không dùng NewABACSystemFromStrings): parser của
// nó tách policy bằng strings.Split(",") thô, vỡ ngay khi rule text chứa dấu
// phẩy — cùng lý do buildCorpusAuthorizer trong expression_cache_test.go đã
// né. Model dùng chung file "../casbin_config/abac_model.conf" của repo.
//
//   - act_read: allow nếu Subject.role == 'admin'; không đụng Resource — dùng
//     để xác nhận nhánh resource rỗng và nhánh Subject-only.
//   - act_locked: allow nếu Subject là admin; NHƯNG deny nếu Resource.locked
//     == true — hai policy cùng khớp cho ra ca "policy deny" (allow && !deny).
//   - act_tag_a: allow nếu Resource.tag == 'a' — dùng cho ca AND đa resource
//     (mọi resource trong danh sách đều phải khớp thì hành động mới allow).
func checkManyPolicyRules() [][]string {
	return [][]string{
		{"*", "Action == 'act_read' && Subject.role == 'admin'", "allow"},
		{"*", "Action == 'act_locked' && Subject.role == 'admin'", "allow"},
		{"*", "Action == 'act_locked' && Resource.locked == true", "deny"},
		{"*", "Action == 'act_tag_a' && Resource.tag == 'a'", "allow"},
	}
}

func setupCheckManyAuthorizer(t *testing.T, fetcher *countingFetcher) *abac.Authorizer {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.csv")
	f, err := os.Create(policyPath)
	require.NoError(t, err)

	w := csv.NewWriter(f)
	for _, rule := range checkManyPolicyRules() {
		row := append([]string{"p"}, rule...)
		require.NoError(t, w.Write(row))
	}
	w.Flush()
	require.NoError(t, w.Error())
	require.NoError(t, f.Close())

	authorizer, _, err := abac.NewABACSystemFromFile(
		"../casbin_config/abac_model.conf", policyPath, fetcher, fetcher, abac.CustomFunctionMap{},
	)
	require.NoError(t, err)
	return authorizer
}

func checkManyBaseFetcher() *countingFetcher {
	f := newCountingFetcher()
	f.withSubject("admin_user", abac.Attributes{"role": "admin"}).
		withSubject("guest_user", abac.Attributes{"role": "guest"})

	f.withResource("res_single", []abac.Attributes{{"locked": false, "tag": "z"}}).
		withResource("res_locked", []abac.Attributes{{"locked": true, "tag": "z"}}).
		withResource("res_empty", []abac.Attributes{}).
		withResource("res_multi_mixed", []abac.Attributes{{"tag": "a"}, {"tag": "b"}}).
		withResource("res_multi_all_a", []abac.Attributes{{"tag": "a"}, {"tag": "a"}})

	f.withSubjectError("ghost_user", abac.ErrSubjectNotFound)
	f.withResourceError("ghost_resource", abac.ErrResourceNotFound)
	return f
}

// assertCheckManyEqualsMapCheck chứng minh CheckMany(actions) ≡ [Check(a) for
// a in actions]: chạy CheckMany một lần, rồi dựng "oracle" bằng cách gọi
// Check() tuần tự cho từng action và so kết quả — cả giá trị (theo ĐÚNG chỉ
// số) lẫn trạng thái lỗi.
func assertCheckManyEqualsMapCheck(
	t *testing.T, authorizer *abac.Authorizer, ctx *context.Context,
	tenantID string, subject, resource interface{}, actions []string,
) {
	t.Helper()

	gotResults, gotErr := authorizer.CheckMany(ctx, tenantID, subject, resource, actions, nil)

	wantResults := make([]bool, 0, len(actions))
	var wantErr error
	for _, action := range actions {
		allowed, err := authorizer.Check(ctx, tenantID, subject, resource, action, nil)
		if err != nil {
			wantErr = err
			break
		}
		wantResults = append(wantResults, allowed)
	}

	if wantErr != nil {
		require.Error(t, gotErr, "map(Check) lỗi nhưng CheckMany không lỗi")
		assert.Nil(t, gotResults)
		return
	}

	require.NoError(t, gotErr)
	assert.Equal(t, wantResults, gotResults, "CheckMany phải khớp map(Check) theo đúng thứ tự")
}

// TestCheckMany_EquivalentToMapCheck là differential test chính: CheckMany
// phải cho kết quả giống hệt việc gọi Check() lần lượt cho từng action, trên
// đủ các nhánh hành vi của enforceOne (resource rỗng, AND đa resource, lỗi
// fetcher, deny ghi đè allow) và trường hợp biên actions rỗng.
func TestCheckMany_EquivalentToMapCheck(t *testing.T) {
	fetcher := checkManyBaseFetcher()
	authorizer := setupCheckManyAuthorizer(t, fetcher)
	ctx := context.Background()

	testCases := []struct {
		name     string
		subject  string
		resource string
		actions  []string
	}{
		{
			name:     "bình thường",
			subject:  "admin_user",
			resource: "res_single",
			actions:  []string{"act_read", "act_locked", "act_tag_a"},
		},
		{
			name:     "resource rỗng",
			subject:  "admin_user",
			resource: "res_empty",
			actions:  []string{"act_read"},
		},
		{
			name:     "AND đa resource — một item không khớp làm hỏng cả cụm",
			subject:  "admin_user",
			resource: "res_multi_mixed",
			actions:  []string{"act_tag_a", "act_read"},
		},
		{
			name:     "AND đa resource — mọi item đều khớp",
			subject:  "admin_user",
			resource: "res_multi_all_a",
			actions:  []string{"act_tag_a"},
		},
		{
			name:     "policy deny ghi đè allow",
			subject:  "admin_user",
			resource: "res_locked",
			actions:  []string{"act_locked"},
		},
		{
			name:     "subject không có policy khớp — deny thường, không lỗi",
			subject:  "guest_user",
			resource: "res_single",
			actions:  []string{"act_read", "act_locked"},
		},
		{
			name:     "danh sách action rỗng",
			subject:  "admin_user",
			resource: "res_single",
			actions:  []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assertCheckManyEqualsMapCheck(t, authorizer, &ctx, "*", tc.subject, tc.resource, tc.actions)
		})
	}
}

// TestCheckMany_SubjectFetcherError xác nhận: lỗi nạp subject làm hỏng cả
// cụm, giống hệt Check() cũng lỗi ở mọi action (vì subject fetch chung).
func TestCheckMany_SubjectFetcherError(t *testing.T) {
	fetcher := checkManyBaseFetcher()
	authorizer := setupCheckManyAuthorizer(t, fetcher)
	ctx := context.Background()
	actions := []string{"act_read", "act_locked"}

	assertCheckManyEqualsMapCheck(t, authorizer, &ctx, "*", "ghost_user", "res_single", actions)

	results, err := authorizer.CheckMany(&ctx, "*", "ghost_user", "res_single", actions, nil)
	require.Error(t, err)
	assert.Nil(t, results)
	assert.ErrorIs(t, err, abac.ErrSubjectNotFound)
}

// TestCheckMany_ResourceFetcherError xác nhận: lỗi nạp resource làm hỏng cả
// cụm, giống hệt Check() cũng lỗi ở mọi action (vì resource fetch chung).
func TestCheckMany_ResourceFetcherError(t *testing.T) {
	fetcher := checkManyBaseFetcher()
	authorizer := setupCheckManyAuthorizer(t, fetcher)
	ctx := context.Background()
	actions := []string{"act_read", "act_locked"}

	assertCheckManyEqualsMapCheck(t, authorizer, &ctx, "*", "admin_user", "ghost_resource", actions)

	results, err := authorizer.CheckMany(&ctx, "*", "admin_user", "ghost_resource", actions, nil)
	require.Error(t, err)
	assert.Nil(t, results)
	assert.ErrorIs(t, err, abac.ErrResourceNotFound)
}

// TestCheckMany_ResultOrderMatchesActionOrder khẳng định riêng phần thứ tự:
// results[i] phải ứng với actions[i], không phải khớp theo tập hợp. Đảo thứ
// tự hai action có kết quả khác nhau (act_locked=false vì resource locked,
// act_read=true) và xác nhận thứ tự đảo theo.
func TestCheckMany_ResultOrderMatchesActionOrder(t *testing.T) {
	fetcher := checkManyBaseFetcher()
	authorizer := setupCheckManyAuthorizer(t, fetcher)
	ctx := context.Background()

	results, err := authorizer.CheckMany(&ctx, "*", "admin_user", "res_locked", []string{"act_locked", "act_read"}, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.False(t, results[0], "act_locked phải bị deny (resource locked)")
	assert.True(t, results[1], "act_read phải allow (không đụng Resource)")

	reversed, err := authorizer.CheckMany(&ctx, "*", "admin_user", "res_locked", []string{"act_read", "act_locked"}, nil)
	require.NoError(t, err)
	require.Len(t, reversed, 2)
	assert.True(t, reversed[0], "act_read ở vị trí 0 phải allow")
	assert.False(t, reversed[1], "act_locked ở vị trí 1 phải deny")
}

// ===== Fetcher đếm: số lần gọi fetcher là hằng số theo số action =====

// countingActions sinh n action tên khác nhau nhưng đều khớp policy
// "act_read" về mặt tiền tố — dùng Action đúng bằng "act_read" lặp lại n
// lần: Enforce() chạy đúng n lần (một Enforce độc lập cho mỗi action), còn
// GetSubjectAttributes/GetResourceAttributes chỉ được gọi một lần duy nhất
// cho cả cụm, bất kể n.
func countingActions(n int) []string {
	actions := make([]string, n)
	for i := range actions {
		actions[i] = "act_read"
	}
	return actions
}

func TestCheckMany_FetcherCallCountIsConstant(t *testing.T) {
	scales := []int{926, 5000}

	for _, n := range scales {
		n := n
		t.Run(fmt.Sprintf("%d action", n), func(t *testing.T) {
			fetcher := checkManyBaseFetcher()
			authorizer := setupCheckManyAuthorizer(t, fetcher)
			ctx := context.Background()
			actions := countingActions(n)

			fetcher.resetCounts()
			results, err := authorizer.CheckMany(&ctx, "*", "admin_user", "res_single", actions, nil)
			require.NoError(t, err)
			require.Len(t, results, n)
			for i, allowed := range results {
				assert.Truef(t, allowed, "act_read tại index %d phải allow", i)
			}

			subjectCalls, resourceCalls := fetcher.counts()
			assert.Equal(t, 1, subjectCalls, "GetSubjectAttributes phải chỉ gọi đúng 1 lần bất kể số action")
			assert.Equal(t, 1, resourceCalls, "GetResourceAttributes phải chỉ gọi đúng 1 lần bất kể số action")
		})
	}
}

// TestCheckMany_FetcherCallCountVsSequentialCheck đo đối chứng: gọi Check()
// tuần tự N lần (cách làm cũ) tốn 2N round-trip fetcher, còn CheckMany chỉ
// tốn 2 — chênh lệch không đổi theo N (hằng số), không phải "giảm còn 2" một
// cách tuyệt đối cho MỌI cách gọi (CheckMany gộp nhiều resource vào một lần
// gọi sẽ tính AND, không phải OR — xem phase-04, không thuộc phạm vi test
// này).
func TestCheckMany_FetcherCallCountVsSequentialCheck(t *testing.T) {
	scales := []int{926, 5000}

	for _, n := range scales {
		n := n
		t.Run(fmt.Sprintf("%d action", n), func(t *testing.T) {
			fetcher := checkManyBaseFetcher()
			authorizer := setupCheckManyAuthorizer(t, fetcher)
			ctx := context.Background()
			actions := countingActions(n)

			fetcher.resetCounts()
			for _, action := range actions {
				_, err := authorizer.Check(&ctx, "*", "admin_user", "res_single", action, nil)
				require.NoError(t, err)
			}
			subjectCallsBefore, resourceCallsBefore := fetcher.counts()
			assert.Equal(t, n, subjectCallsBefore, "gọi Check tuần tự: subject fetch tăng tuyến tính theo N")
			assert.Equal(t, n, resourceCallsBefore, "gọi Check tuần tự: resource fetch tăng tuyến tính theo N")

			fetcher.resetCounts()
			_, err := authorizer.CheckMany(&ctx, "*", "admin_user", "res_single", actions, nil)
			require.NoError(t, err)
			subjectCallsAfter, resourceCallsAfter := fetcher.counts()
			assert.Equal(t, 1, subjectCallsAfter, "CheckMany: subject fetch không đổi theo N")
			assert.Equal(t, 1, resourceCallsAfter, "CheckMany: resource fetch không đổi theo N")
		})
	}
}
