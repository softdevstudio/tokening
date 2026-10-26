package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/store"
)

type credential struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
	Value    string `json:"value,omitempty"`
}

func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, call matcher.Call, receipt store.Consumption, body []byte, query url.Values) {
	start := time.Now()
	status := 0
	failed := true
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer cancel()
		if err := g.store.CompleteUpstream(ctx, receipt, status, time.Since(start), failed); err != nil {
			g.logger.Printf("could not record upstream outcome for grant %s: %v", receipt.Grant, err)
		}
	}()
	target, err := g.store.Target(r.Context(), call.Target)
	if err != nil || target.Kind != "http" {
		writeError(w, 502, "upstream_error", "The configured upstream is unavailable. The use remains consumed.")
		return
	}
	base, err := url.Parse(target.Destination)
	if err != nil || base.Hostname() == "" || (base.Scheme != "https" && base.Scheme != "http") || base.User != nil || base.RawQuery != "" || base.Fragment != "" || strings.Contains(base.EscapedPath(), "%") {
		writeError(w, 502, "upstream_error", "The configured upstream URL is invalid. The use remains consumed.")
		return
	}
	base.Path = strings.TrimRight(base.Path, "/") + call.Path
	base.RawPath = ""
	base.RawQuery = query.Encode()
	// A non-replayable body and fresh connections prevent automatic replays.
	var reader io.Reader
	if body != nil {
		reader = io.NopCloser(bytes.NewReader(body))
	}
	upstream, err := http.NewRequestWithContext(r.Context(), call.Method, base.String(), reader)
	if err != nil {
		writeError(w, 502, "upstream_error", "Could not construct the upstream request. The use remains consumed.")
		return
	}
	for _, name := range []string{"Accept", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"} {
		if value := r.Header.Get(name); value != "" {
			upstream.Header.Set(name, value)
		}
	}
	if body != nil {
		upstream.Header.Set("Content-Type", "application/json")
	}
	plain, err := g.store.Credential(r.Context(), call.Target, g.vault)
	if err != nil {
		writeError(w, 502, "upstream_error", "Could not load the upstream credential. The use remains consumed.")
		return
	}
	err = inject(upstream, target.CredentialType, plain)
	clear(plain)
	if err != nil {
		writeError(w, 502, "upstream_error", "The stored credential is invalid. The use remains consumed.")
		return
	}
	response, err := g.client.Do(upstream)
	if err != nil {
		writeError(w, 502, "upstream_error", "The upstream request failed. The use remains consumed.")
		return
	}
	defer response.Body.Close()
	status = response.StatusCode
	copyResponseHeaders(w.Header(), response.Header)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, err = io.Copy(w, response.Body)
	failed = err != nil || status >= 400
}
func inject(r *http.Request, kind string, plain []byte) error {
	fields, err := parseObject(plain)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	switch kind {
	case "basic":
		allowed["username"] = true
		allowed["password"] = true
	case "bearer":
		allowed["value"] = true
	case "header":
		allowed["name"] = true
		allowed["value"] = true
	default:
		return errors.New("unsupported credential type")
	}
	for name := range fields {
		if !allowed[name] {
			return errors.New("invalid credential field")
		}
	}
	var c credential
	if err = json.Unmarshal(plain, &c); err != nil {
		return err
	}
	switch kind {
	case "basic":
		if c.Username == "" || c.Password == "" || strings.Contains(c.Username, ":") {
			return errors.New("invalid basic credential")
		}
		r.SetBasicAuth(c.Username, c.Password)
	case "bearer":
		if !validHeaderValue(c.Value) || strings.ContainsAny(c.Value, " \t") {
			return errors.New("invalid bearer credential")
		}
		r.Header.Set("Authorization", "Bearer "+c.Value)
	case "header":
		if !validHeaderName(c.Name) || !validHeaderValue(c.Value) || reservedHeader(c.Name) {
			return errors.New("invalid credential header")
		}
		r.Header.Set(c.Name, c.Value)
	}
	return nil
}
func validHeaderValue(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 32 || r >= 127 {
			return false
		}
	}
	return true
}
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}
func reservedHeader(name string) bool {
	n := http.CanonicalHeaderKey(name)
	switch n {
	case "Host", "Content-Length", "Content-Type", "Connection", "Transfer-Encoding", "Upgrade", "Proxy-Authorization", "Proxy-Authenticate", "Trailer", "Te", "Accept":
		return true
	}
	return strings.HasPrefix(n, "Mcp-")
}
func copyResponseHeaders(out, in http.Header) {
	blocked := map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Set-Cookie": true, "Www-Authenticate": true, "Authentication-Info": true, "Proxy-Authentication-Info": true}
	for _, value := range in.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			blocked[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	allowed := map[string]bool{"Content-Type": true, "Content-Length": true, "Content-Encoding": true, "Content-Language": true, "Content-Disposition": true, "Etag": true, "Last-Modified": true, "Location": true, "Retry-After": true, "Accept-Ranges": true, "Content-Range": true, "Date": true, "Vary": true, "Expires": true}
	for name, values := range in {
		canonical := http.CanonicalHeaderKey(name)
		if blocked[canonical] || !allowed[canonical] {
			continue
		}
		for _, value := range values {
			out.Add(name, value)
		}
	}
}

// ValidateCredential checks the upload format without sending a request.
func ValidateCredential(kind string, plain []byte) error {
	return inject(&http.Request{Header: make(http.Header)}, kind, plain)
}
