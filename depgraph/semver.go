package depgraph

import (
	"fmt"
	"strconv"
	"strings"
)

// version is a parsed semantic version (major.minor.patch, optional
// pre-release ignored for ordering stability: pre-release sorts lower).
type version struct {
	major, minor, patch int
	pre                 string
	raw                 string
}

func parseVersion(s string) (version, error) {
	v := version{raw: s}
	s = strings.TrimPrefix(s, "v")
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, v.pre = s[:i], s[i+1:]
	}
	if i := strings.IndexByte(core, '+'); i >= 0 {
		core = core[:i]
	}
	parts := strings.Split(core, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return v, fmt.Errorf("invalid version %q", s)
	}
	nums := []int{0, 0, 0}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("invalid version %q", s)
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	return v, nil
}

// compareVersions returns -1, 0 or 1. Deterministic total order.
func compareVersions(a, b version) int {
	if a.major != b.major {
		return cmpInt(a.major, b.major)
	}
	if a.minor != b.minor {
		return cmpInt(a.minor, b.minor)
	}
	if a.patch != b.patch {
		return cmpInt(a.patch, b.patch)
	}
	// Release > pre-release; pre-releases compare lexically.
	if a.pre == b.pre {
		return 0
	}
	if a.pre == "" {
		return 1
	}
	if b.pre == "" {
		return -1
	}
	return strings.Compare(a.pre, b.pre)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// sortVersions returns the versions sorted ascending; error on any invalid
// version string.
func sortVersions(vs []string) ([]string, error) {
	parsed := make([]version, len(vs))
	for i, s := range vs {
		v, err := parseVersion(s)
		if err != nil {
			return nil, err
		}
		parsed[i] = v
	}
	// Insertion sort with stable comparison on parsed versions.
	for i := 1; i < len(parsed); i++ {
		for j := i; j > 0 && compareVersions(parsed[j-1], parsed[j]) > 0; j-- {
			parsed[j-1], parsed[j] = parsed[j], parsed[j-1]
		}
	}
	out := make([]string, len(parsed))
	for i, v := range parsed {
		out[i] = v.raw
	}
	return out, nil
}

// constraint is a conjunction of comparator clauses.
type constraint struct {
	clauses []clause
}

type clause struct {
	op  string // ">=", "<=", ">", "<", "=", "!=", "~>", "^"
	ver version
}

// parseConstraint parses a space/comma-separated constraint expression.
// Empty string matches any version.
func parseConstraint(s string) (constraint, error) {
	var c constraint
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return c, nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' })
	for _, f := range fields {
		cl, err := parseClause(f)
		if err != nil {
			return c, err
		}
		c.clauses = append(c.clauses, cl)
	}
	return c, nil
}

func parseClause(f string) (clause, error) {
	ops := []string{">=", "<=", "!=", "~>", "^", ">", "<", "="}
	for _, op := range ops {
		if strings.HasPrefix(f, op) {
			v, err := parseVersion(strings.TrimPrefix(f, op))
			if err != nil {
				return clause{}, err
			}
			return clause{op: op, ver: v}, nil
		}
	}
	// Bare version means exact match.
	v, err := parseVersion(f)
	if err != nil {
		return clause{}, fmt.Errorf("invalid constraint clause %q", f)
	}
	return clause{op: "=", ver: v}, nil
}

// matches reports whether raw version satisfies the constraint.
func (c constraint) matches(raw string) bool {
	v, err := parseVersion(raw)
	if err != nil {
		return false
	}
	for _, cl := range c.clauses {
		if !cl.matches(v) {
			return false
		}
	}
	return true
}

func (cl clause) matches(v version) bool {
	cmp := compareVersions(v, cl.ver)
	switch cl.op {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "=":
		return cmp == 0
	case "!=":
		return cmp != 0
	case "~>": // >= ver, < next minor (or next major if only major given)
		if cmp < 0 {
			return false
		}
		upper := cl.ver
		upper.minor++
		upper.patch = 0
		upper.pre = ""
		return compareVersions(v, upper) < 0
	case "^": // >= ver, < next major
		if cmp < 0 {
			return false
		}
		upper := cl.ver
		upper.major++
		upper.minor, upper.patch = 0, 0
		upper.pre = ""
		return compareVersions(v, upper) < 0
	}
	return false
}
