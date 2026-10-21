// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package dotenv

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Expected values were checked against python-dotenv 1.2.4 itself, so an
// existing .env reads the same after the Go rewrite.
func TestParseMatchesPythonDotenv(t *testing.T) {
	type want map[string]*string
	s := func(v string) *string { return &v }
	cases := []struct {
		text string
		want want
	}{
		{"A=b", want{"A": s("b")}},
		{"export A=b", want{"A": s("b")}},
		{"A = b ", want{"A": s("b")}},
		{`A="b c"`, want{"A": s("b c")}},
		{"A='b c'", want{"A": s("b c")}},
		{`A="b\nc"`, want{"A": s("b\nc")}},
		{`A='b\nc'`, want{"A": s(`b\nc`)}},
		{`A="b\"c"`, want{"A": s(`b"c`)}},
		{`A='b\'c'`, want{"A": s("b'c")}},
		{`A="b\\"`, want{"A": s(`b\`)}},
		{"A=\"multi\nline\"", want{"A": s("multi\nline")}},
		{"A=b # comment", want{"A": s("b")}},
		{"A=b#notcomment", want{"A": s("b#notcomment")}},
		{"A= # comment", want{"A": s("")}},
		{"A=#novalue", want{"A": s("#novalue")}},
		{`A="b" # comment`, want{"A": s("b")}},
		{"# only a comment\nA=b", want{"A": s("b")}},
		{"A=", want{"A": s("")}},
		{"A", want{"A": nil}},
		{"'A'=b", want{"A": s("b")}},
		{"\ufeffA=b", want{"A": s("b")}},
		{"A=b\r\nC=d\rE=f", want{"A": s("b"), "C": s("d"), "E": s("f")}},
		{"A=b\nA=c", want{"A": s("c")}},
		{"=b\nC=d", want{"C": s("d")}},
		{"A=\"unterminated\nC=d", want{"C": s("d")}},
		{"A=x\nB=${A}y", want{"A": s("x"), "B": s("xy")}},
		{"B=${MISSING:-dflt}", want{"B": s("dflt")}},
		{"B='${A}'", want{"B": s("")}},
		{"A=x\nB=$A", want{"A": s("x"), "B": s("$A")}},
	}
	for _, tc := range cases {
		got := Resolve(Parse(tc.text), map[string]string{}, true)
		gotW := want{}
		for k, v := range got {
			if v.Set {
				gotW[k] = s(v.S)
			} else {
				gotW[k] = nil
			}
		}
		if len(gotW) != len(tc.want) {
			t.Errorf("%q: got %d keys %v, want %d", tc.text, len(gotW), keysOf(gotW), len(tc.want))
			continue
		}
		for k, w := range tc.want {
			g, ok := gotW[k]
			switch {
			case !ok:
				t.Errorf("%q: missing key %s", tc.text, k)
			case (g == nil) != (w == nil):
				t.Errorf("%q: %s set-ness differs", tc.text, k)
			case g != nil && *g != *w:
				t.Errorf("%q: %s = %q, want %q", tc.text, k, *g, *w)
			}
		}
	}
}

func keysOf(m map[string]*string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestOriginalTextRoundTrips(t *testing.T) {
	text := "# c\nexport A=1\n'B'=\"x\ny\"\n\nbad line here\nC=3"
	var b strings.Builder
	for _, binding := range Parse(text) {
		b.WriteString(binding.Original)
	}
	if b.String() != text {
		t.Fatalf("bindings do not cover the source:\n%q\n%q", b.String(), text)
	}
}

func TestLayerPrecedence(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env.shared", "T_A=shared\nT_B=shared\nT_C=shared\nT_REF=${T_ENV}\n")
	write(t, dir, ".env", "T_B=local\nT_X=${T_A}-${T_C}\n")
	got := Layer(dir, map[string]string{"T_C": "process", "T_ENV": "fromenv"})
	wantKV := map[string]string{
		"T_A": "shared", "T_B": "local", "T_C": "process",
		"T_X": "shared-process", "T_REF": "fromenv", "T_ENV": "fromenv",
	}
	if !reflect.DeepEqual(got, wantKV) {
		t.Fatalf("Layer = %v, want %v", got, wantKV)
	}
}

func TestLayerOverrideInterpolationPrefersFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "T_X=file\nT_Y=${T_X}\n")
	got := Layer(dir, map[string]string{"T_X": "env"})
	if got["T_Y"] != "file" || got["T_X"] != "file" {
		t.Fatalf("got %v", got)
	}
}

func TestLayerIgnoresSymlinksAndBareKeys(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "real", "T_LINKED=1\n")
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	write(t, dir, ".env.shared", "T_BARE\n")
	got := Layer(dir, map[string]string{})
	if len(got) != 0 {
		t.Fatalf("expected nothing loaded, got %v", got)
	}
}

func TestMissingFilesAreEmpty(t *testing.T) {
	if got := Layer(t.TempDir(), map[string]string{"K": "v"}); !reflect.DeepEqual(got, map[string]string{"K": "v"}) {
		t.Fatalf("got %v", got)
	}
}

func write(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func resolvedOf(text string) map[string]string {
	out := map[string]string{}
	for k, v := range Resolve(Parse(text), map[string]string{}, true) {
		if v.Set {
			out[k] = v.S
		}
	}
	return out
}

func TestMergeKeepsUnmanagedBytesAndUpdatesManagedKeys(t *testing.T) {
	existing := "# operator notes\n" +
		"export AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n" +
		"'AWS_SECRET_ACCESS_KEY'=s3cr3t\n" +
		"CUSTOM-KEY=value\n" +
		"MULTI=\"line one\nline two\"\n" +
		"BASE=archive\n" +
		"EMAIL_S3_BUCKET=${BASE}-bucket\n" +
		"AWS_REGION=\"us-east-1\"\n" +
		"EARLY=${AWS_REGION}\n" +
		"AWS_REGION=us-west-2\n"
	desired := map[string]string{
		"EMAIL_S3_BUCKET": "${BASE}-bucket", "AWS_REGION": "eu-west-1", "EXPLORER_AUTH_MODE": "central",
	}
	got := Merge(existing, desired, []string{"EMAIL_S3_BUCKET", "AWS_REGION", "EXPLORER_AUTH_MODE"}, nil)
	if !strings.HasPrefix(got, strings.Split(existing, "AWS_REGION=us-west-2")[0]) {
		t.Fatalf("unmanaged prefix changed:\n%s", got)
	}
	after, before := resolvedOf(got), resolvedOf(existing)
	if after["EMAIL_S3_BUCKET"] != "archive-bucket" || after["AWS_REGION"] != "eu-west-1" ||
		after["EXPLORER_AUTH_MODE"] != "central" || after["EARLY"] != "us-east-1" {
		t.Fatalf("merged values wrong: %v\n%s", after, got)
	}
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "CUSTOM-KEY", "MULTI", "BASE"} {
		if after[k] != before[k] {
			t.Errorf("%s changed: %q -> %q", k, before[k], after[k])
		}
	}
}

func TestMergeLeavesProvisionBlockAlone(t *testing.T) {
	block := ProvisionBegin + "x) ──\nEMAIL_S3_BUCKET=prov\nP=1\n" + ProvisionEnd + "x) ──\n"
	got := Merge("KEEP=1\n\n"+block, map[string]string{"EMAIL_S3_BUCKET": "prov", "AWS_REGION": "us-east-2"},
		[]string{"EMAIL_S3_BUCKET", "AWS_REGION"}, nil)
	if !strings.Contains(got, block) {
		t.Fatalf("block changed:\n%s", got)
	}
	outside := strings.Replace(got, block, "", 1)
	if strings.Contains(outside, "EMAIL_S3_BUCKET") || !strings.Contains(outside, `AWS_REGION="us-east-2"`) {
		t.Fatalf("unexpected merge:\n%s", got)
	}
}

func TestMergeLeavesProvisionedKeyOutsideBlock(t *testing.T) {
	block := ProvisionBegin + "x) ──\nEMAIL_S3_BUCKET=prod-bucket\n" + ProvisionEnd + "x) ──\n"
	existing := "EMAIL_S3_BUCKET=\"\"\n\n" + block
	vals := EffectiveValues(existing, nil, []string{"EMAIL_S3_BUCKET"})
	if vals["EMAIL_S3_BUCKET"] != "prod-bucket" {
		t.Fatalf("values = %v", vals)
	}
	if got := Merge(existing, map[string]string{"EMAIL_S3_BUCKET": "prod-bucket"}, nil, nil); got != existing {
		t.Fatalf("merge changed the file:\n%s", got)
	}
}

func TestMergeKeepsInterpolatedSpelling(t *testing.T) {
	existing := "MODE=central\nEXPLORER_AUTH_MODE=${MODE}\n"
	if v := EffectiveValues(existing, nil, []string{"EXPLORER_AUTH_MODE"}); v["EXPLORER_AUTH_MODE"] != "central" {
		t.Fatalf("values = %v", v)
	}
	if got := Merge(existing, map[string]string{"EXPLORER_AUTH_MODE": "central"}, nil, nil); got != existing {
		t.Fatalf("merge rewrote an equal value:\n%s", got)
	}
}

func TestMergeResolvesThroughSharedLayer(t *testing.T) {
	shared := SharedValues("MODE=central\n")
	existing := "EXPLORER_AUTH_MODE=${MODE}\n"
	if v := EffectiveValues(existing, shared, []string{"EXPLORER_AUTH_MODE"}); v["EXPLORER_AUTH_MODE"] != "central" {
		t.Fatalf("values = %v", v)
	}
	if got := Merge(existing, map[string]string{"EXPLORER_AUTH_MODE": "central"}, nil, shared); got != existing {
		t.Fatalf("got %q", got)
	}
}

func TestSharedOnlyKeyStaysShared(t *testing.T) {
	shared := SharedValues("EXPLORER_AUTH_MODE=central\n")
	if v := EffectiveValues("OTHER=1\n", shared, []string{"EXPLORER_AUTH_MODE"}); v["EXPLORER_AUTH_MODE"] != "central" {
		t.Fatalf("values = %v", v)
	}
	if got := Merge("OTHER=1\n", map[string]string{"EXPLORER_AUTH_MODE": "central"}, nil, shared); got != "OTHER=1\n" {
		t.Fatalf("shared value was pinned locally: %q", got)
	}
	if got := Merge("OTHER=1\n", map[string]string{"EXPLORER_AUTH_MODE": "elcano"}, nil, shared); !strings.Contains(got, `EXPLORER_AUTH_MODE="elcano"`) {
		t.Fatalf("explicit override missing: %q", got)
	}
}

func TestSharedInterpolationIgnoresCallerEnvironment(t *testing.T) {
	t.Setenv("MODE", "ELCANO")
	shared := SharedValues("EXPLORER_AUTH_MODE=${MODE:-central}\n")
	if shared["EXPLORER_AUTH_MODE"] != "central" {
		t.Fatalf("caller environment leaked: %v", shared)
	}
}

func TestQuoteRoundTripsAwkwardValues(t *testing.T) {
	value := `a"b\c $d ${X}`
	got := Parse("K=" + Quote(value) + "\n")
	if len(got) != 1 || got[0].Value != value {
		t.Fatalf("round trip = %+v", got)
	}
}
