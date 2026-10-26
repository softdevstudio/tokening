// Package number compares JSON numbers without floating-point rounding.
package number

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// Number retains the JSON spelling of a policy bound.
type Number string

// Parse accepts bounded JSON number tokens. Bounding both token length and
// exponent keeps exact arithmetic predictable for untrusted inputs.
func Parse(s string) (*big.Rat, error) {
	if len(s) == 0 || len(s) > 256 || !(s[0] == '-' || s[0] >= '0' && s[0] <= '9') || !json.Valid([]byte(s)) {
		return nil, fmt.Errorf("invalid JSON number")
	}
	if at := strings.IndexAny(s, "eE"); at >= 0 {
		e, err := strconv.Atoi(s[at+1:])
		if err != nil || e < -1024 || e > 1024 {
			return nil, fmt.Errorf("number exponent is outside supported range")
		}
	}
	n, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("invalid JSON number")
	}
	return n, nil
}
func (n *Number) UnmarshalJSON(raw []byte) error {
	if _, err := Parse(string(raw)); err != nil {
		return err
	}
	*n = Number(raw)
	return nil
}
func (n Number) MarshalJSON() ([]byte, error) {
	if _, err := Parse(string(n)); err != nil {
		return nil, err
	}
	return []byte(n), nil
}
