// Package admin exposes operator-only APIs. Never mount it on the agent port.
package admin

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/softdevstudio/tokening/internal/panel"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/gateway"
	"github.com/softdevstudio/tokening/internal/jsonobject"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

type Options struct{ DemoReplayFile string }

type Handler struct {
	demoReplayFile string
	store          *store.Store
	vault          *vault.Vault
	token          [32]byte
}

func New(s *store.Store, v *vault.Vault, token string, options ...Options) (*Handler, error) {
	if s == nil || v == nil || len(token) < 32 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return nil, errors.New("admin token must contain 32 to 512 non-whitespace characters")
	}
	for _, character := range token {
		if character < 33 || character > 126 {
			return nil, errors.New("admin token must use visible ASCII characters")
		}
	}
	file := ""
	if len(options) > 0 {
		file = options[0].DemoReplayFile
	}
	return &Handler{store: s, vault: v, token: sha256.Sum256([]byte(token)), demoReplayFile: file}, nil
}
func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Browser origins have no admin API access, even with a valid bearer.
	if len(r.Header.Values("Origin")) != 0 {
		problem(w, 403, "Browser origins are not allowed on the admin API.")
		return
	}
	if r.Method == "GET" && r.URL.RawQuery == "" {
		asset := ""
		switch r.URL.Path {
		case "/admin/panel":
			asset = "panel.html"
		case "/admin/panel.js":
			asset = "panel.js"
		case "/admin/panel.css":
			asset = "panel.css"
		}
		if asset != "" {
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
			contentType := "text/html; charset=utf-8"
			if asset == "panel.js" {
				contentType = "application/javascript; charset=utf-8"
			}
			if asset == "panel.css" {
				contentType = "text/css; charset=utf-8"
			}
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(panel.Asset(asset))
			return
		}
	}
	auth := r.Header.Values("Authorization")
	valid := false
	if len(auth) == 1 {
		parts := strings.Fields(auth[0])
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && len(parts[1]) <= 512 {
			hash := sha256.Sum256([]byte(parts[1]))
			valid = subtle.ConstantTimeCompare(hash[:], h.token[:]) == 1
		}
	}
	if !valid {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tokening-admin"`)
		problem(w, 401, "Present the admin bearer token.")
		return
	}
	if strings.Contains(r.URL.EscapedPath(), "%") || strings.Contains(r.URL.Path, "//") {
		problem(w, 400, "Use plain admin paths.")
		return
	}
	path := r.URL.Path
	switch {
	case path == "/admin/demo" && r.Method == "GET":
		if r.URL.RawQuery != "" {
			problem(w, 400, "Unexpected query parameters.")
			return
		}
		if h.demoReplayFile == "" {
			problem(w, 404, "No demo snapshot is configured.")
			return
		}
		file, err := os.Open(h.demoReplayFile)
		if err != nil {
			problem(w, 503, "Demo snapshot is not ready.")
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > panel.MaxReplayBytes {
			problem(w, 503, "Demo snapshot is unavailable.")
			return
		}
		snapshot, err := panel.Decode(file)
		if err != nil {
			problem(w, 503, "Demo snapshot is unavailable.")
			return
		}
		reply(w, 200, snapshot)
	case path == "/admin/templates" && r.Method == "GET":
		if r.URL.RawQuery != "" {
			problem(w, 400, "Unexpected query parameters.")
			return
		}
		templates, err := h.store.ListTemplates(r.Context())
		if err != nil {
			problem(w, 500, "Could not read templates.")
			return
		}
		reply(w, 200, templates)
	case path == "/admin/targets" && r.Method == "POST":
		var request struct {
			Name       string          `json:"name"`
			Credential json.RawMessage `json:"credential"`
		}
		if !decode(w, r, &request) {
			return
		}
		info, err := h.store.Target(r.Context(), request.Name)
		if errors.Is(err, store.ErrTargetUnknown) {
			problem(w, 404, "Target is not in the policy.")
			return
		}
		if err != nil {
			problem(w, 500, "Could not read target.")
			return
		}
		if len(request.Credential) > vault.MaxCredentialBytes {
			problem(w, 413, "Credential exceeds 64 KiB.")
			return
		}
		if gateway.ValidateCredential(info.CredentialType, request.Credential) != nil {
			problem(w, 400, "Credential does not match the target's credential format.")
			return
		}
		defer clear(request.Credential)
		if err = h.store.SetCredential(r.Context(), request.Name, h.vault, request.Credential); err != nil {
			problem(w, 500, "Could not save credential.")
			return
		}
		reply(w, 200, map[string]string{"target": request.Name, "status": "stored"})
	case path == "/admin/grants" && r.Method == "POST":
		var request struct {
			Template string                     `json:"template"`
			Uses     int                        `json:"uses"`
			TTL      string                     `json:"ttl"`
			Args     map[string]json.RawMessage `json:"args"`
			Query    map[string]json.RawMessage `json:"query"`
			IssuedTo string                     `json:"issued_to"`
			Reason   string                     `json:"reason"`
			IssuedBy string                     `json:"issued_by"`
		}
		if !decode(w, r, &request) {
			return
		}
		ttl, err := time.ParseDuration(request.TTL)
		if err != nil {
			problem(w, 400, "TTL must be a duration such as 15m.")
			return
		}
		issued, err := h.store.IssueGrant(r.Context(), store.IssueRequest{Template: request.Template, Uses: request.Uses, TTL: ttl, Args: request.Args, Query: request.Query, IssuedTo: request.IssuedTo, Reason: request.Reason, IssuedBy: request.IssuedBy})
		if errors.Is(err, store.ErrInvalidIssue) || errors.Is(err, store.ErrTemplateUnknown) {
			problem(w, 400, "Grant does not fit an active template. Check bindings, uses, TTL and actor fields.")
			return
		}
		if err != nil {
			problem(w, 500, "Could not issue grant.")
			return
		}
		reply(w, 201, issued)
	case strings.HasPrefix(path, "/admin/grants/"):
		suffix := strings.TrimPrefix(path, "/admin/grants/")
		id, revoke := strings.CutSuffix(suffix, "/revoke")
		if id == "" || strings.Contains(id, "/") || (!revoke && r.Method != "GET") || (revoke && r.Method != "POST") {
			problem(w, 404, "Unknown admin route.")
			return
		}
		var info store.GrantInfo
		var err error
		if revoke {
			var request struct {
				Actor string `json:"actor"`
			}
			if !decode(w, r, &request) {
				return
			}
			if strings.TrimSpace(request.Actor) == "" {
				problem(w, 400, "Revocation needs an actor.")
				return
			}
			info, err = h.store.RevokeGrant(r.Context(), id, request.Actor)
		} else {
			if r.URL.RawQuery != "" {
				problem(w, 400, "Unexpected query parameters.")
				return
			}
			info, err = h.store.InspectGrant(r.Context(), id)
		}
		if errors.Is(err, store.ErrGrantUnknown) {
			problem(w, 404, "Grant does not exist.")
			return
		}
		if err != nil {
			problem(w, 500, "Could not read or revoke grant.")
			return
		}
		reply(w, 200, info)
	case (path == "/admin/decisions" || path == "/admin/decisions.jsonl") && r.Method == "GET":
		h.decisions(w, r, path)
	default:
		problem(w, 404, "Unknown admin route.")
	}
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.URL.RawQuery != "" {
		problem(w, 400, "Unexpected query parameters.")
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		problem(w, 415, "Use unencoded application/json.")
		return false
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, gateway.MaxBodyBytes+1))
	if err != nil || len(data) > gateway.MaxBodyBytes {
		problem(w, 413, "Request body exceeds 1 MiB.")
		return false
	}
	defer clear(data)
	if _, err = jsonobject.Decode(data); err != nil {
		problem(w, 400, "Use one JSON object without duplicate keys.")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		problem(w, 400, "Invalid request fields.")
		return false
	}
	return true
}
func (h *Handler) decisions(w http.ResponseWriter, r *http.Request, path string) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		problem(w, 400, "Invalid decision query.")
		return
	}
	for key, values := range query {
		if len(values) != 1 || (key != "since" && key != "grant" && key != "follow") {
			problem(w, 400, "Invalid decision query.")
			return
		}
	}
	cursor := int64(0)
	if value, ok := query["since"]; ok {
		cursor, err = strconv.ParseInt(value[0], 10, 64)
		if err != nil || cursor < 0 {
			problem(w, 400, "Invalid decision cursor.")
			return
		}
	}
	filter := store.DecisionFilter{AfterID: cursor, GrantID: query.Get("grant")}
	if path == "/admin/decisions.jsonl" {
		if query.Has("follow") {
			problem(w, 400, "Export cannot follow.")
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Trailer", "Tokening-Export-Complete")
		if _, err = h.store.ExportDecisions(r.Context(), w, filter); err == nil {
			w.Header().Set("Tokening-Export-Complete", "true")
		}
		return
	}
	if query.Get("follow") == "" {
		records, err := h.store.ListDecisions(r.Context(), filter, 100)
		if err != nil {
			problem(w, 500, "Could not read decisions.")
			return
		}
		reply(w, 200, records)
		return
	}
	if query.Get("follow") != "true" {
		problem(w, 400, "follow must be true.")
		return
	}
	flush, ok := w.(http.Flusher)
	if !ok {
		problem(w, 500, "Streaming is unavailable.")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		records, err := h.store.ListDecisions(r.Context(), filter, 100)
		if err != nil {
			return
		}
		for _, record := range records {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
			data, err := json.Marshal(record)
			if err != nil {
				return
			}
			if _, err = fmt.Fprintf(w, "id: %d\nevent: decision\ndata: %s\n\n", record.ID, data); err != nil {
				return
			}
			filter.AfterID = record.ID
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err = io.WriteString(w, ": keepalive\n\n"); err != nil {
			return
		}
		flush.Flush()
		if len(records) == 100 {
			continue
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
