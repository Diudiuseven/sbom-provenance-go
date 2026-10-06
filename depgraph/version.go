package depgraph

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseVersion 解析 "MAJOR.MINOR.PATCH"。
func ParseVersion(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("depgraph: bad version %q", s)
	}
	var v Version
	var err error
	if v.Major, err = strconv.Atoi(parts[0]); err != nil {
		return Version{}, fmt.Errorf("depgraph: bad version %q", s)
	}
	if v.Minor, err = strconv.Atoi(parts[1]); err != nil {
		return Version{}, fmt.Errorf("depgraph: bad version %q", s)
	}
	if v.Patch, err = strconv.Atoi(parts[2]); err != nil {
		return Version{}, fmt.Errorf("depgraph: bad version %q", s)
	}
	return v, nil
}

// String 返回版本的规范字符串。
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare 比较两个版本：-1/0/1。
func (v Version) Compare(o Version) int {
	if v.Major != o.Major {
		return cmpInt(v.Major, o.Major)
	}
	if v.Minor != o.Minor {
		return cmpInt(v.Minor, o.Minor)
	}
	return cmpInt(v.Patch, o.Patch)
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// SatisfiedBy 判定版本是否满足约束。判定只依赖约束本身，与求值顺序无关。
func (c Constraint) SatisfiedBy(v Version) bool {
	if c.Exact != nil {
		return v.Compare(*c.Exact) == 0
	}
	if v.Compare(c.Min) < 0 {
		return false
	}
	if c.HasMax && v.Compare(c.Max) >= 0 {
		return false
	}
	return true
}

// MarshalJSON 以 "MAJOR.MINOR.PATCH" 字符串编码。
func (v Version) MarshalJSON() ([]byte, error) {
	return []byte(`"` + v.String() + `"`), nil
}

// UnmarshalJSON 解析 "MAJOR.MINOR.PATCH" 字符串。
func (v *Version) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	parsed, err := ParseVersion(s)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}
