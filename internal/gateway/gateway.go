// Package gateway exposes the agent-facing REST permission boundary.
package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

const MaxBodyBytes = 1 << 20

type Options struct {
	AllowedOrigins []string
	ErrorLog       *log.Logger
}
type Gateway struct {
	store   *store.Store
	vault   *vault.Vault
	client  *http.Client
	origins map[string]bool
	logger  *log.Logger
}

func New(s *store.Store, v *vault.Vault, options Options) (*Gateway, error) {
	if s == nil || v == nil {
		return nil, errors.New("gateway needs a store and vault")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10}
	g := &Gateway{store: s, vault: v, origins: map[string]bool{}, client: &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	g.logger = options.ErrorLog
	if g.logger == nil {
		g.logger = log.Default()
	}
	for _, origin := range options.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("invalid allowed origin")
		}
		g.origins[origin] = true
	}
	return g, nil
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || len(origins) == 1 && !g.origins[origins[0]] {
		writeError(w, 403, "origin_not_allowed", "This origin is not allowed.")
		return
	}
	if r.URL.Path != "/grant" && !strings.HasPrefix(r.URL.Path, "/http/") {
		http.NotFound(w, r)
		return
	}
	secret, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tokening"`)
		writeError(w, 401, string(matcher.GrantUnknown), "Present one grant bearer token in Authorization.")
		return
	}
	if r.URL.Path == "/grant" {
		g.describe(w, r, secret)
		return
	}
	g.rest(w, r, secret)
}
func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 512 {
		return "", false
	}
	return parts[1], true
}
func (g *Gateway) describe(w http.ResponseWriter, r *http.Request, secret string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, 405, "method_not_allowed", "Use GET for grant self-description.")
		return
	}
	if r.URL.RawQuery != "" {
		writeError(w, 400, "invalid_request", "Grant self-description accepts no query parameters.")
		return
	}
	grant, err := g.store.ResolveGrant(r.Context(), secret)
	if err != nil {
		writeError(w, 500, "storage_error", "Could not read this grant.")
		return
	}
	if grant == nil {
		writeError(w, 401, string(matcher.GrantUnknown), "No grant matches this token.")
		return
	}
	state := "issued"
	switch {
	case grant.RevokedAt != nil:
		state = "revoked"
	case !time.Now().Before(grant.ExpiresAt):
		state = "expired"
	case grant.UsesLeft == 0:
		state = "exhausted"
	case grant.LastUsedAt != nil:
		state = "active"
	}
	action := grant.Template.Tool
	if action == "" {
		action = grant.Template.Method + " " + grant.Template.Path
	}
	extra := grant.Template.AdditionalArgs
	if extra == "" {
		extra = "refuse"
	}
	description := fmt.Sprintf("Grant %s is %s. It allows %s on target %s, with %d use(s) left until %s. Undeclared fields: %s.", grant.ID, state, action, grant.Template.Target, grant.UsesLeft, grant.ExpiresAt.Format(time.RFC3339Nano), extra)
	writeJSON(w, 200, map[string]any{"grant": grant.ID, "state": state, "target": grant.Template.Target, "tool": grant.Template.Tool, "method": grant.Template.Method, "path": grant.Template.Path, "bound_args": grant.Args, "bound_query": grant.Query, "arguments": grant.Template.Args, "query": grant.Template.Query, "additional_args": extra, "uses_left": grant.UsesLeft, "expires_at": grant.ExpiresAt, "description": description})
}
func (g *Gateway) rest(w http.ResponseWriter, r *http.Request, secret string) {
	if strings.Contains(r.URL.EscapedPath(), "%") || strings.Contains(r.URL.Path, "//") {
		writeError(w, 400, "invalid_request", "Use a plain path without encoded characters or repeated slashes.")
		return
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/http/")
	target, path, ok := strings.Cut(suffix, "/")
	if !ok || target == "" {
		writeError(w, 400, "invalid_request", "Use /http/target/path.")
		return
	}
	path = "/" + path
	call := matcher.Call{Target: target, Method: r.Method, Path: path}
	grant, err := g.store.ResolveGrant(r.Context(), secret)
	if err != nil {
		writeError(w, 500, "storage_error", "Could not read this grant.")
		return
	}
	if grant == nil || grant.TargetKind != "http" || grant.Template.Target != target {
		g.refuse(w, r, secret, call)
		return
	}
	if coding := r.Header.Get("Content-Encoding"); coding != "" && coding != "identity" {
		writeError(w, 415, "unsupported_media_type", "Encoded request bodies are not supported.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		writeError(w, 400, "invalid_request", "Could not read the request body.")
		return
	}
	if len(body) > MaxBodyBytes {
		writeError(w, 413, "request_too_large", "JSON body exceeds 1 MiB.")
		return
	}
	if len(bytes.TrimSpace(body)) > 0 {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			writeError(w, 415, "unsupported_media_type", "REST bodies must use application/json.")
			return
		}
		call.Args, err = parseObject(body)
		if err != nil {
			writeError(w, 400, "invalid_request", "Use one JSON object without duplicate keys.")
			return
		}
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, 400, "invalid_request", "Invalid query parameters.")
		return
	}
	call.Query = make(map[string]json.RawMessage, len(query))
	for name, values := range query {
		if len(values) != 1 || strings.EqualFold(name, "_method") || isPathArgument(grant.Template.Path, name) {
			writeError(w, 400, "invalid_request", "Repeated, path-shadowing or method-override query parameters are not allowed.")
			return
		}
		if _, exists := call.Args[name]; exists {
			writeError(w, 400, "invalid_request", "A field cannot appear in both body and query.")
			return
		}
		raw, err := queryScalar(values[0], grant.Template.Query[name], grant.Query[name])
		if err != nil {
			writeError(w, 400, "invalid_request", "Query parameter has an invalid scalar encoding.")
			return
		}
		call.Query[name] = raw
	}
	for name := range call.Args {
		if strings.EqualFold(name, "_method") {
			writeError(w, 400, "invalid_request", "Method overrides are not allowed.")
			return
		}
	}
	// Re-encode the exact parsed object and query used for matching. No raw body
	// or unvalidated query string takes a separate path to the upstream.
	normalizedBody := []byte(nil)
	if len(bytes.TrimSpace(body)) > 0 {
		normalizedBody, err = json.Marshal(call.Args)
		if err != nil {
			writeError(w, 400, "invalid_request", "Invalid JSON body.")
			return
		}
	}
	normalizedQuery := url.Values{}
	for name, raw := range call.Query {
		var value any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err = d.Decode(&value); err != nil {
			writeError(w, 400, "invalid_request", "Invalid query value.")
			return
		}
		switch v := value.(type) {
		case string:
			normalizedQuery.Set(name, v)
		case json.Number:
			normalizedQuery.Set(name, string(v))
		case bool:
			if v {
				normalizedQuery.Set(name, "true")
			} else {
				normalizedQuery.Set(name, "false")
			}
		}
	}
	receipt, err := g.store.Consume(r.Context(), secret, call)
	if err != nil {
		writeError(w, 500, "storage_error", "Could not commit this authorization.")
		return
	}
	if !receipt.Allowed {
		status := 403
		if receipt.Code == matcher.GrantUnknown {
			status = 401
		}
		writeJSON(w, status, receipt.Decision)
		return
	}
	g.forward(w, r, call, receipt, normalizedBody, normalizedQuery)
}
func (g *Gateway) refuse(w http.ResponseWriter, r *http.Request, secret string, call matcher.Call) {
	d, err := g.store.Consume(r.Context(), secret, call)
	if err != nil {
		writeError(w, 500, "storage_error", "Could not record this decision.")
		return
	}
	if d.Allowed {
		writeError(w, 500, "storage_error", "Unexpected grant transport.")
		return
	}
	status := 403
	if d.Code == matcher.GrantUnknown {
		status = 401
	}
	writeJSON(w, status, d.Decision)
}
func queryScalar(text string, rule policy.Constraint, binding matcher.Binding) (json.RawMessage, error) {
	kind := rule.Type
	if kind == "" && len(binding.Value) > 0 {
		var v any
		d := json.NewDecoder(bytes.NewReader(binding.Value))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		switch v.(type) {
		case json.Number:
			kind = "number"
		case bool:
			kind = "boolean"
		}
	}
	if kind == "number" || kind == "integer" || kind == "boolean" {
		raw := json.RawMessage(text)
		var value any
		d := json.NewDecoder(strings.NewReader(text))
		d.UseNumber()
		if !json.Valid(raw) || d.Decode(&value) != nil {
			return nil, errors.New("invalid scalar")
		}
		switch value.(type) {
		case json.Number:
			if kind == "boolean" {
				return nil, errors.New("wrong scalar type")
			}
		case bool:
			if kind != "boolean" {
				return nil, errors.New("wrong scalar type")
			}
		default:
			return nil, errors.New("wrong scalar type")
		}
		return raw, nil
	}
	return json.Marshal(text)
}
func isPathArgument(path, name string) bool { return strings.Contains(path, "{"+name+"}") }
func writeError(w http.ResponseWriter, status int, code, reason string) {
	writeJSON(w, status, map[string]string{"code": code, "reason": reason})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	if status == 401 && w.Header().Get("WWW-Authenticate") == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tokening"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
