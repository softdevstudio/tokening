// Package panel shares the read-only admin UI and self-contained demo replay.
package panel

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/jsonobject"
)

//go:embed assets/*
var assets embed.FS

const MaxReplayBytes = 1 << 20

type Grant struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	Tool        string    `json:"tool"`
	State       string    `json:"state"`
	InitialUses int       `json:"initial_uses"`
	UsesLeft    int       `json:"uses_left"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Reason      string    `json:"reason"`
	BoundArgs   struct {
		ID struct {
			Value json.RawMessage `json:"value"`
		} `json:"id"`
	} `json:"bound_args"`
}
type Decision struct {
	ID              int64     `json:"id"`
	GrantID         string    `json:"grant_id"`
	At              time.Time `json:"at"`
	Action          string    `json:"action"`
	Outcome         string    `json:"outcome"`
	Code            string    `json:"code"`
	Reason          string    `json:"reason"`
	AuthorizationID *int64    `json:"authorization_id"`
}
type Post struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
	Status  string `json:"status"`
}

// Replay is an allowlist projection. Unknown source fields, including secrets,
// credentials and arbitrary agent output, never reach the page or snapshot API.
type Replay struct {
	Schema    int        `json:"schema"`
	Passed    bool       `json:"passed"`
	Grants    []Grant    `json:"grants"`
	Audit     []Decision `json:"audit"`
	WordPress struct {
		Posts   []Post `json:"posts"`
		Before  []Post `json:"before"`
		Writes  int    `json:"writes"`
		Deletes int    `json:"deletes"`
		Version string `json:"wordpress_version"`
		Adapter string `json:"adapter_version"`
	} `json:"wordpress"`
	Agent struct {
		Isolation       string `json:"isolation"`
		ParallelWinners int    `json:"parallel_winners"`
		Steps           []Step `json:"steps"`
	} `json:"agent"`
}

// Step is one scripted agent request. Arguments are reduced to short scalars
// in Decode, so the page shows what was asked without copying agent output.
type Step struct {
	Step      string         `json:"step"`
	Tool      string         `json:"tool,omitempty"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Code      string         `json:"code,omitempty"`
	Decisions []struct {
		Code string `json:"code"`
	} `json:"decisions,omitempty"`
	Tools []string `json:"tools,omitempty"`
}

const (
	maxSteps       = 20
	maxStepArgs    = 8
	maxShortText   = 60
	maxGrantReason = 120
)

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// shortScalars keeps numbers, booleans and short strings. Anything else is
// dropped rather than rendered.
func shortScalars(in map[string]any) map[string]any {
	out := map[string]any{}
	names := make([]string, 0, len(in))
	for key := range in {
		names = append(names, key)
	}
	sort.Strings(names) // stable output when arguments are dropped
	for _, key := range names {
		value := in[key]
		if len(out) == maxStepArgs || len(key) > 32 {
			continue
		}
		switch v := value.(type) {
		case json.Number, bool:
			out[key] = v
		case string:
			if len([]rune(v)) <= maxShortText {
				out[key] = v
			}
		}
	}
	return out
}

func Asset(name string) []byte { data, _ := assets.ReadFile("assets/" + name); return data }
func Decode(input io.Reader) (Replay, error) {
	var replay Replay
	data, err := io.ReadAll(io.LimitReader(input, MaxReplayBytes+1))
	if err != nil {
		return replay, err
	}
	if len(data) > MaxReplayBytes {
		return replay, errors.New("replay exceeds 1 MiB")
	}
	if _, err = jsonobject.Decode(data); err != nil {
		return replay, errors.New("replay must be one JSON object without duplicate keys")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&replay) != nil {
		return Replay{}, errors.New("invalid replay fields")
	}
	if len(replay.Agent.Steps) > maxSteps || len(replay.WordPress.Before) > 100 {
		return Replay{}, errors.New("replay has too many steps or posts")
	}
	for i := range replay.Agent.Steps {
		step := &replay.Agent.Steps[i]
		step.Step, step.Tool = clip(step.Step, 40), clip(step.Tool, 64)
		step.Arguments = shortScalars(step.Arguments)
		if len(step.Decisions) > 4 {
			step.Decisions = step.Decisions[:4]
		}
		if len(step.Tools) > 8 {
			step.Tools = step.Tools[:8]
		}
		for j := range step.Tools {
			step.Tools[j] = clip(step.Tools[j], 64)
		}
	}
	for i := range replay.Grants {
		replay.Grants[i].Reason = clip(replay.Grants[i].Reason, maxGrantReason)
	}
	if replay.Schema != 1 || !replay.Passed || len(replay.Grants) == 0 || len(replay.Grants) > 20 || len(replay.Audit) == 0 || len(replay.Audit) > 5000 || len(replay.WordPress.Posts) == 0 || len(replay.WordPress.Posts) > 100 {
		return Replay{}, errors.New("expected a passed schema-1 demo replay")
	}
	grants := map[string]Grant{}
	uses := map[string]int{}
	for _, grant := range replay.Grants {
		if grant.ID == "" || grant.InitialUses < 1 || grant.UsesLeft < 0 || grant.UsesLeft > grant.InitialUses || grant.ExpiresAt.IsZero() {
			return Replay{}, errors.New("invalid replay grant")
		}
		if _, exists := grants[grant.ID]; exists {
			return Replay{}, errors.New("duplicate replay grant")
		}
		grants[grant.ID] = grant
	}
	var prior int64
	authorizations := map[int64]string{}
	completed := map[int64]bool{}
	for _, decision := range replay.Audit {
		if decision.ID <= prior || decision.At.IsZero() {
			return Replay{}, errors.New("replay decision IDs must increase and timestamps must be present")
		}
		prior = decision.ID
		if _, exists := grants[decision.GrantID]; !exists {
			return Replay{}, errors.New("replay decision names an unknown grant")
		}
		if decision.AuthorizationID != nil {
			receipt := *decision.AuthorizationID
			if authorizations[receipt] != decision.GrantID || completed[receipt] || decision.Code != "allowed" || decision.Outcome != "allowed" {
				return Replay{}, errors.New("invalid replay completion link")
			}
			completed[receipt] = true
		} else if decision.Code == "allowed" && decision.Outcome == "allowed" {
			authorizations[decision.ID] = decision.GrantID
			uses[decision.GrantID]++
		} else if decision.Outcome != "refused" {
			return Replay{}, errors.New("invalid replay decision outcome")
		}
	}
	if len(authorizations) != len(completed) || replay.WordPress.Writes != len(authorizations) || replay.WordPress.Deletes != 0 {
		return Replay{}, errors.New("replay writes do not match completed authorizations")
	}
	for id, grant := range grants {
		if grant.InitialUses-uses[id] != grant.UsesLeft {
			return Replay{}, errors.New("replay counters do not match authorizations")
		}
	}
	return replay, nil
}
func Export(input io.Reader, output io.Writer) error {
	replay, err := Decode(input)
	if err != nil {
		return err
	}
	data, err := json.Marshal(replay)
	if err != nil {
		return err
	} // HTML escaping is intentionally enabled.
	page := string(Asset("panel.html"))
	style, script := Asset("panel.css"), Asset("panel.js")
	hash := func(data []byte) string { sum := sha256.Sum256(data); return base64.StdEncoding.EncodeToString(sum[:]) }
	csp := `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-` + hash(script) + `'; style-src 'sha256-` + hash(style) + `'; connect-src 'none'; base-uri 'none'; form-action 'none'">`
	page = strings.Replace(page, "<!-- replay-policy -->", csp, 1)
	page = strings.Replace(page, `<link rel="stylesheet" href="/admin/panel.css">`, "<style>"+string(style)+"</style>", 1)
	page = strings.Replace(page, `<script defer src="/admin/panel.js"></script>`, "<script>"+string(script)+"</script>", 1)
	page = strings.Replace(page, `id="replay-data">null</script>`, `id="replay-data">`+string(data)+`</script>`, 1)
	// The deferred admin script is moved to the end for its inline replay form.
	start := strings.Index(page, "<script>"+string(script))
	inline := "<script>" + string(script) + "</script>"
	if start < 0 {
		return errors.New("replay template is missing its script")
	}
	page = strings.Replace(page, inline, "", 1)
	page = strings.Replace(page, "</body>", inline+"</body>", 1)
	_, err = io.Copy(output, bytes.NewBufferString(page))
	return err
}
