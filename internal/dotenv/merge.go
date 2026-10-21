// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package dotenv

import (
	"sort"
	"strings"
)

// The block `explorer provision` owns inside .env; it replaces the block
// whole, so bootstrap never edits a key set inside it.
const (
	ProvisionBegin = "# ── managed by explorer provision ("
	ProvisionEnd   = "# ── end explorer provision ("
)

// SharedValues resolves a .env.shared text the way the service sees it,
// against nothing but itself: the caller's own environment (a root shell
// running bootstrap) is not what the service gets, so it must not leak in.
func SharedValues(text string) map[string]string {
	out := map[string]string{}
	for k, v := range Resolve(Parse(text), map[string]string{}, true) {
		if v.Set {
			out[k] = v.S
		}
	}
	return out
}

// EffectiveValues returns the value the service actually uses for each of
// keys: .env resolved over shared (interpolation, the provision block and
// later duplicates included), falling back to .env.shared for keys .env
// does not set.
func EffectiveValues(envText string, shared map[string]string, keys []string) map[string]string {
	effective := map[string]string{}
	for k, v := range shared {
		effective[k] = v
	}
	for k, v := range Resolve(Parse(envText), shared, true) {
		if v.Set {
			effective[k] = v.S
		}
	}
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := effective[k]; ok {
			out[k] = v
		}
	}
	return out
}

// Quote renders value as a double-quoted dotenv value that Parse reads back
// unchanged.
func Quote(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

// Merge updates the managed keys of an existing .env in place and keeps
// every other byte. desired holds the managed keys and the values bootstrap
// wants; order lists them in template order for keys that must be appended.
//
//   - Only the effective (last) binding of a key outside the provision block
//     is rewritten, and only when its value (literal, or after ${VAR}
//     resolution) actually differs: unchanged lines keep the operator's
//     exact text.
//   - A key the provision block sets is left alone everywhere.
//   - A key .env does not set is appended under "# Added by bootstrap",
//     unless .env.shared already supplies that same value (copying it would
//     pin it against fleet-wide changes).
func Merge(existing string, desired map[string]string, order []string, shared map[string]string) string {
	bindings := Parse(existing)
	resolved := Resolve(bindings, shared, true)
	inside := provisionBlockFlags(bindings)
	provisioned := map[string]bool{}
	for i, b := range bindings {
		if inside[i] && b.HasKey {
			provisioned[b.Key] = true
		}
	}
	last := map[string]int{}
	for i, b := range bindings {
		if _, managed := desired[b.Key]; b.HasKey && !inside[i] && managed && !provisioned[b.Key] {
			last[b.Key] = i
		}
	}

	var out strings.Builder
	for i, b := range bindings {
		want, managed := desired[b.Key]
		idx, isLast := last[b.Key]
		if !b.HasKey || !managed || !isLast || idx != i ||
			(b.HasValue && want == b.Value) || (resolved[b.Key].Set && want == resolved[b.Key].S) {
			out.WriteString(b.Original)
			continue
		}
		text := b.Original
		lead := text[:len(text)-len(strings.TrimLeftFunc(text, IsPySpace))]
		tail := ""
		if strings.HasSuffix(text, "\n") || strings.HasSuffix(text, "\r") {
			tail = "\n"
		}
		out.WriteString(lead + b.Key + "=" + Quote(want) + tail)
	}

	missing := missingKeys(desired, order, last, provisioned, shared)
	merged := out.String()
	if len(missing) == 0 {
		return merged
	}
	if merged != "" && !strings.HasSuffix(merged, "\n") {
		merged += "\n"
	}
	merged += "\n# Added by bootstrap\n"
	for _, k := range missing {
		merged += k + "=" + Quote(desired[k]) + "\n"
	}
	return merged
}

// provisionBlockFlags marks each binding that sits inside a provision block.
func provisionBlockFlags(bindings []Binding) []bool {
	inside := make([]bool, len(bindings))
	in := false
	for i, b := range bindings {
		if !b.HasKey && strings.Contains(b.Original, ProvisionBegin) {
			in = true
			inside[i] = true
			continue
		}
		inside[i] = in
		if !b.HasKey && strings.Contains(b.Original, ProvisionEnd) {
			in = false
		}
	}
	return inside
}

// missingKeys are the managed keys .env does not bind and that must be
// appended, in template order.
func missingKeys(desired map[string]string, order []string, last map[string]int,
	provisioned map[string]bool, shared map[string]string,
) []string {
	var missing []string
	seen := map[string]bool{}
	for _, k := range append(append([]string{}, order...), sortedKeys(desired)...) {
		if seen[k] {
			continue
		}
		seen[k] = true
		if _, ok := desired[k]; !ok {
			continue
		}
		if _, ok := last[k]; ok || provisioned[k] {
			continue
		}
		if sv, ok := shared[k]; ok && sv == desired[k] {
			continue
		}
		missing = append(missing, k)
	}
	return missing
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
