// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ElcanoTek/explorer/internal/config"
)

// The testdata/*.eml fixtures were written by Python's email package
// (EmailMessage, as the Python test suite built them), so the Go parser is
// exercised on exactly the MIME the old tests used. All addresses are
// synthetic.

var (
	day      = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	received = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
)

type fakeObj struct {
	data     []byte
	modified time.Time
}

// fakeStore is an in-memory Store. List pages by pageSize so continuation
// is exercised; Get mimics S3's InvalidRange for a ranged read of an empty
// object.
type fakeStore struct {
	mu       sync.Mutex
	objects  map[string]fakeObj
	pageSize int
	gets     int
	fullGets int
	failKey  string
}

func newFake(objects map[string][]byte) *fakeStore {
	f := &fakeStore{objects: map[string]fakeObj{}, pageSize: 1000}
	for k, v := range objects {
		f.objects[k] = fakeObj{data: v, modified: received}
	}
	return f
}

func (f *fakeStore) List(ctx context.Context, prefix, token string, maxKeys int32) (ListPage, error) {
	if err := ctx.Err(); err != nil {
		return ListPage{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	start := 0
	if token != "" {
		fmt.Sscanf(token, "%d", &start)
	}
	size := min(int(maxKeys), f.pageSize)
	end := min(start+size, len(keys))
	page := ListPage{}
	for _, k := range keys[start:end] {
		page.Objects = append(page.Objects, Object{Key: k, LastModified: f.objects[k].modified, Size: int64(len(f.objects[k].data))})
	}
	if end < len(keys) {
		page.NextToken = fmt.Sprint(end)
	}
	return page, nil
}

func (f *fakeStore) Get(ctx context.Context, key string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	if key == f.failKey {
		return nil, errors.New("boom")
	}
	obj, ok := f.objects[key]
	if !ok {
		return nil, ErrNoSuchKey
	}
	if maxBytes <= 0 {
		f.fullGets++
		return obj.data, nil
	}
	if len(obj.data) == 0 {
		return nil, ErrInvalidRange
	}
	return obj.data[:min(int64(len(obj.data)), maxBytes)], nil
}

func settings() config.Settings {
	s, err := config.FromEnv(map[string]string{"EMAIL_S3_BUCKET": "test-bucket"})
	if err != nil {
		panic(err)
	}
	return s
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var oneDay = []DateRange{{Start: day, End: day}}

func TestBuildSearchPrefixes(t *testing.T) {
	got := BuildSearchPrefixes("emails/", "emails/%Y/%m/%d/", 62, day, day.AddDate(0, 0, 2))
	want := []string{"emails/2026/06/03/", "emails/2026/06/02/", "emails/2026/06/01/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := BuildSearchPrefixes("emails/", "emails/%Y/%m/%d/", 30, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), day); !reflect.DeepEqual(got, []string{"emails/"}) {
		t.Fatalf("wide span: %v", got)
	}
	if got := BuildSearchPrefixes("emails/", "", 62, day, day); !reflect.DeepEqual(got, []string{"emails/"}) {
		t.Fatalf("no format: %v", got)
	}
	if got := BuildSearchPrefixes("e/", "e/%Y-%j/%b/%%x/%Q", 5, day, day); got[0] != "e/2026-152/Jun/%x/%Q" {
		t.Fatalf("strftime: %v", got)
	}
}

func TestFetchHeaders(t *testing.T) {
	in := New(newFake(map[string][]byte{
		"emails/2026/06/01/empty": nil,
		"emails/2026/06/01/msg1":  fixture(t, "hello.eml"),
	}), settings())
	h, err := in.fetchHeaders(context.Background(), "emails/2026/06/01/empty")
	if err != nil || h != (headers{}) {
		t.Fatalf("zero-byte: %+v %v", h, err)
	}
	h, err = in.fetchHeaders(context.Background(), "emails/2026/06/01/msg1")
	if err != nil || h.Subject != "Hello world" || !strings.Contains(h.From, "reporting@ssp.example") {
		t.Fatalf("headers: %+v %v", h, err)
	}
}

func TestExactSearchFiltersBySender(t *testing.T) {
	in := New(newFake(map[string][]byte{
		"emails/2026/06/01/a": fixture(t, "alpha.eml"),
		"emails/2026/06/01/b": fixture(t, "beta.eml"),
	}), settings())
	rows, scanned, err := in.Search(context.Background(), oneDay, ExactQuery{Sender: "BETA@two"}, 10)
	if err != nil || scanned != 2 || len(rows) != 1 || rows[0].Subject != "B" {
		t.Fatalf("rows=%+v scanned=%d err=%v", rows, scanned, err)
	}
	if rows[0].ReceivedAt != "2026-06-01T12:00:00+00:00" || rows[0].SizeBytes == 0 {
		t.Fatalf("row = %+v", rows[0])
	}
}

func TestExactSearchStopsAtMaxInListingOrder(t *testing.T) {
	objects := map[string][]byte{}
	for i := 0; i < 40; i++ {
		objects[fmt.Sprintf("emails/2026/06/01/m%02d", i)] = fixture(t, "hello.eml")
	}
	fake := newFake(objects)
	fake.pageSize = 7
	for i := 0; i < 40; i++ {
		k := fmt.Sprintf("emails/2026/06/01/m%02d", i)
		o := fake.objects[k]
		o.modified = received.Add(time.Duration(i) * time.Minute)
		fake.objects[k] = o
	}
	rows, scanned, err := New(fake, settings()).Search(context.Background(), oneDay, ExactQuery{}, 5)
	if err != nil || scanned != 40 || len(rows) != 5 {
		t.Fatalf("len=%d scanned=%d err=%v", len(rows), scanned, err)
	}
	// The first five in listing order, newest first.
	for i, r := range rows {
		if want := fmt.Sprintf("emails/2026/06/01/m%02d", 4-i); r.S3Key != want {
			t.Fatalf("row %d = %s, want %s", i, r.S3Key, want)
		}
	}
	if fake.gets > 5+fetchWorkers {
		t.Fatalf("fetched %d headers for 5 results", fake.gets)
	}
}

func TestListingFiltersWindowsPrefixesAndDuplicates(t *testing.T) {
	fake := newFake(map[string][]byte{
		"emails/2026/06/01/":     fixture(t, "hello.eml"), // the prefix itself
		"emails/2026/06/01/in":   fixture(t, "hello.eml"),
		"emails/2026/06/01/late": fixture(t, "hello.eml"),
		"emails/2026/06/02/next": fixture(t, "hello.eml"),
	})
	o := fake.objects["emails/2026/06/01/late"]
	o.modified = day.AddDate(0, 0, 3) // filed under the wrong day
	fake.objects["emails/2026/06/01/late"] = o
	in := New(fake, settings())
	objs, scanned, err := in.listObjects(context.Background(), []DateRange{oneDay[0], oneDay[0]})
	if err != nil || scanned != 1 || objs[0].Key != "emails/2026/06/01/in" {
		t.Fatalf("objs=%+v scanned=%d err=%v", objs, scanned, err)
	}
}

func TestFuzzySearch(t *testing.T) {
	fake := newFake(map[string][]byte{
		"emails/2026/06/01/a": fixture(t, "northwind.eml"),
		"emails/2026/06/01/b": fixture(t, "unrelated.eml"),
	})
	in := New(fake, settings())
	rows, _, err := in.SearchFuzzy(context.Background(), oneDay, []string{"northwind"}, FuzzyFields{Subject: true}, false, 10)
	if err != nil || len(rows) != 1 || rows[0].Subject != "Northwind daily report" || rows[0].FuzzyScore < 3 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	if fake.fullGets != 0 {
		t.Fatal("subject-only search downloaded bodies")
	}
	rows, _, err = in.SearchFuzzy(context.Background(), oneDay, []string{" NorthWind ", ""}, FuzzyFields{Subject: true, Sender: true, Body: true}, false, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("body search rows=%+v err=%v", rows, err)
	}
	// Subject hit: 3 + 1; body-only hit: 1 + 1.
	if rows[0].Subject != "Northwind daily report" || rows[0].FuzzyScore != 4 || rows[1].FuzzyScore != 2 {
		t.Fatalf("scores: %+v", rows)
	}
	if fake.fullGets != 1 {
		t.Fatalf("body downloads = %d, want only the undecided message", fake.fullGets)
	}
	rows, _, _ = in.SearchFuzzy(context.Background(), oneDay, []string{"northwind", "daily"}, FuzzyFields{Subject: true}, true, 10)
	if len(rows) != 1 || rows[0].MatchedTerms != 2 || rows[0].FuzzyScore != 7 {
		t.Fatalf("match all: %+v", rows)
	}
	if rows, n, _ := in.SearchFuzzy(context.Background(), oneDay, []string{" ", ""}, FuzzyFields{Subject: true}, false, 10); rows != nil || n != 0 {
		t.Fatal("blank keywords searched")
	}
}

func TestViewPagePaginates(t *testing.T) {
	objects := map[string][]byte{}
	for i := 0; i < 5; i++ {
		objects[fmt.Sprintf("emails/2026/06/01/m%d", i)] = fixture(t, "hello.eml")
	}
	objects["emails/2026/06/02/other-day"] = fixture(t, "hello.eml")
	in := New(newFake(objects), settings())
	rows, next, scanned, err := in.ViewPage(context.Background(), oneDay, 10, nil)
	if err != nil || len(rows) != 5 || next != nil || scanned != 5 {
		t.Fatalf("rows=%d next=%v scanned=%d err=%v", len(rows), next, scanned, err)
	}
	var keys []string
	var cursor *CursorState
	for page := 0; page < 5; page++ {
		rows, next, _, err := in.ViewPage(context.Background(), oneDay, 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			keys = append(keys, r.S3Key)
		}
		if next == nil {
			break
		}
		cursor = next
	}
	if len(keys) != 5 || keys[0] != "emails/2026/06/01/m0" || keys[4] != "emails/2026/06/01/m4" {
		t.Fatalf("paged keys = %v", keys)
	}
}

func TestGetEmailExposesHeadersAndAttachments(t *testing.T) {
	key := "emails/2026/06/01/msg1"
	in := New(newFake(map[string][]byte{key: fixture(t, "cc_attach.eml")}), settings())
	e, err := in.GetEmail(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if e.Cc != "copy@example.com" || e.ReplyTo != "replies@ssp.example" || e.Bcc != "" || e.Subject != "Daily report" {
		t.Fatalf("headers: %+v", e)
	}
	if len(e.Attachments) != 1 || e.Attachments[0].Filename != "report.pdf" || e.Attachments[0].SizeBytes != 7 {
		t.Fatalf("attachments: %+v", e.Attachments)
	}
	if e.BodyPreviewType != "plain" || !strings.Contains(e.BodyPreview, "plain body") || e.BodyPreviewHTML != "" {
		t.Fatalf("preview: %+v", e)
	}
}

func TestGetEmailRewritesCIDImages(t *testing.T) {
	key := "emails/2026/06/01/msg2"
	in := New(newFake(map[string][]byte{key: fixture(t, "cid.eml")}), settings())
	e, err := in.GetEmail(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	want := `/attachment?s3_key=emails%2F2026%2F06%2F01%2Fmsg2&amp;filename=inline_logo123.png`
	if !strings.Contains(e.BodyPreviewHTML, want) || strings.Contains(e.BodyPreviewHTML, "cid:logo123") || e.BodyPreviewType != "html" {
		t.Fatalf("html = %q", e.BodyPreviewHTML)
	}
	att, err := in.Attachment(context.Background(), key, "inline_logo123.png")
	if err != nil || string(att.Data) != "\x89PNG-fake-bytes" || att.ContentType != "image/png" {
		t.Fatalf("inline download: %+v %v", att, err)
	}
}

func TestGetEmailUnicode(t *testing.T) {
	key := "emails/2026/06/01/u"
	in := New(newFake(map[string][]byte{key: fixture(t, "unicode.eml")}), settings())
	e, err := in.GetEmail(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if e.Subject != "Café résumé ✓" || e.From != "Zoë <zoe@example.com>" || e.Attachments[0].Filename != "résumé.pdf" {
		t.Fatalf("%q %q %+v", e.Subject, e.From, e.Attachments)
	}
	att, err := in.Attachment(context.Background(), key, "résumé.pdf")
	if err != nil || string(att.Data) != "RES" || att.Name != "résumé.pdf" {
		t.Fatalf("%+v %v", att, err)
	}
}

func TestPlainPreview(t *testing.T) {
	key := "emails/2026/06/01/msg3"
	in := New(newFake(map[string][]byte{key: fixture(t, "plain.eml")}), settings())
	e, err := in.GetEmail(context.Background(), key)
	if err != nil || !strings.Contains(e.BodyPreview, "hello body") || !strings.Contains(e.BodyPreviewLinked, "hello body") {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestAttachmentDownload(t *testing.T) {
	key := "emails/2026/06/01/msg1"
	in := New(newFake(map[string][]byte{
		key:                    fixture(t, "cc_attach.eml"),
		"emails/2026/06/01/tr": fixture(t, "traversal.eml"),
	}), settings())
	att, err := in.Attachment(context.Background(), key, "report.pdf")
	if err != nil || string(att.Data) != "PDFDATA" || att.Name != "report.pdf" {
		t.Fatalf("%+v %v", att, err)
	}
	att, err = in.Attachment(context.Background(), "emails/2026/06/01/tr", "../../evil.txt")
	if err != nil || att.Name != "evil.txt" || string(att.Data) != "X" {
		t.Fatalf("traversal: %+v %v", att, err)
	}
	if _, err := in.Attachment(context.Background(), key, "nope.pdf"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := in.Attachment(context.Background(), key, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
}

func TestCancellationAndErrors(t *testing.T) {
	objects := map[string][]byte{}
	for i := 0; i < 30; i++ {
		objects[fmt.Sprintf("emails/2026/06/01/m%02d", i)] = fixture(t, "hello.eml")
	}
	fake := newFake(objects)
	in := New(fake, settings())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := in.Search(ctx, oneDay, ExactQuery{}, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled search: %v", err)
	}
	fake.failKey = "emails/2026/06/01/m17"
	if _, _, err := in.Search(context.Background(), oneDay, ExactQuery{}, 100); err == nil || err.Error() != "boom" {
		t.Fatalf("store error: %v", err)
	}
}

func TestUnsetBucket(t *testing.T) {
	st, err := NewS3Store(context.Background(), config.Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.List(context.Background(), "x", "", 1); !errors.Is(err, ErrBucketUnset) {
		t.Fatalf("got %v", err)
	}
}

func TestHelpers(t *testing.T) {
	if got := Quote("emails/2026/a b+c~é"); got != "emails%2F2026%2Fa%20b%2Bc~%C3%A9" {
		t.Fatalf("Quote = %q", got)
	}
	if got := inlineFilenameForCID("logo@x.é", "image/jpeg"); got != "inline_logo_x._.jpg" {
		t.Fatalf("inline name = %q", got)
	}
	if got := inlineFilenameForCID("", "application/x-unknown"); got != "inline_inline.bin" {
		t.Fatalf("inline name = %q", got)
	}
	if got := basenameInlineRef(` "<https://x.example/a/Logo%20One.PNG?v=1>" `); got != "logo one.png" {
		t.Fatalf("basename = %q", got)
	}
	if got := normalizeCID(" <<ID@Host>> "); got != "id@host" {
		t.Fatalf("cid = %q", got)
	}
	if got := isoformat(time.Date(2026, 1, 2, 3, 4, 5, 6000, time.FixedZone("x", 3600))); got != "2026-01-02T02:04:05.000006+00:00" {
		t.Fatalf("isoformat = %q", got)
	}
}
