package matcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/softdevstudio/tokening/internal/number"
)

type value struct{ kind, text string }

func scalar(raw json.RawMessage) (value, error) {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return value{}, fmt.Errorf("must be a valid JSON scalar")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var decoded any
	if err := d.Decode(&decoded); err != nil {
		return value{}, fmt.Errorf("must be a valid JSON scalar")
	}
	switch v := decoded.(type) {
	case string:
		if !validSurrogates(strings.TrimSpace(string(raw))) {
			return value{}, fmt.Errorf("must contain valid Unicode")
		}
		return value{"string", v}, nil
	case bool:
		return value{"boolean", strconv.FormatBool(v)}, nil
	case json.Number:
		if _, err := number.Parse(string(v)); err != nil {
			return value{}, err
		}
		return value{"number", string(v)}, nil
	default:
		return value{}, fmt.Errorf("must be a non-null scalar; objects and arrays are not supported")
	}
}
func equal(a, b json.RawMessage) bool {
	av, err := scalar(a)
	if err != nil {
		return false
	}
	bv, err := scalar(b)
	if err != nil || av.kind != bv.kind {
		return false
	}
	if av.kind == "number" {
		an, _ := number.Parse(av.text)
		bn, _ := number.Parse(bv.text)
		return an.Cmp(bn) == 0
	}
	return av.text == bv.text
}

// encoding/json replaces lone UTF-16 surrogates with U+FFFD. Refuse them rather
// than matching a replacement character while an upstream sees different data.
func validSurrogates(s string) bool {
	for i := 1; i < len(s)-1; i++ {
		if s[i] != '\\' {
			continue
		}
		i++
		if s[i] != 'u' {
			continue
		}
		n, _ := strconv.ParseUint(s[i+1:i+5], 16, 16)
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return false
		}
		if n >= 0xD800 && n <= 0xDBFF {
			if i+6 >= len(s) || s[i+1] != '\\' || s[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(s[i+3:i+7], 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}
