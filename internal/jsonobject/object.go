package jsonobject

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

func Decode(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("JSON must be UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := uniqueJSON(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("expected one JSON object")
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(data, &out); err != nil || out == nil {
		return nil, errors.New("expected a JSON object")
	}
	return out, nil
}
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate or invalid JSON key")
			}
			seen[name] = true
			if err = uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}
