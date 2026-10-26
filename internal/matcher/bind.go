package matcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/softdevstudio/tokening/internal/policy"
)

// Bind validates issue-time scalar values before storing bindings. Hash rules
// produce a digest only; their supplied plaintext must never reach the store.
func Bind(rules map[string]policy.Constraint, values map[string]json.RawMessage) (map[string]Binding, error) {
	out := make(map[string]Binding, len(values))
	for _, name := range keys(values) {
		rule, ok := rules[name]
		if !ok || rule.Bind == "" {
			return nil, fmt.Errorf("field %s cannot be bound", name)
		}
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("field %s has an invalid rule", name)
		}
		raw := values[name]
		if err := checkValue(rule, raw); err != nil {
			return nil, fmt.Errorf("field %s: %w", name, err)
		}
		if rule.SHA256 {
			value, _ := scalar(raw)
			sum := sha256.Sum256([]byte(value.text))
			out[name] = Binding{SHA256: hex.EncodeToString(sum[:])}
		} else {
			out[name] = Binding{Value: append(json.RawMessage(nil), raw...)}
		}
	}
	for _, name := range keys(rules) {
		rule := rules[name]
		if rule.Bind == "required" || rule.SHA256 {
			if _, ok := out[name]; !ok {
				return nil, fmt.Errorf("field %s needs a binding", name)
			}
		}
	}
	return out, nil
}
