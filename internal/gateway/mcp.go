package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/softdevstudio/tokening/internal/matcher"
	"github.com/softdevstudio/tokening/internal/version"
)

const mcpVersion = "2025-06-18"

func rpc(w http.ResponseWriter, id json.RawMessage, result any, code int, message string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	out := map[string]any{"jsonrpc": "2.0", "id": id}
	if code != 0 {
		out["error"] = map[string]any{"code": code, "message": message}
	} else {
		out["result"] = result
	}
	writeJSON(w, 200, out)
}

func (g *Gateway) mcp(w http.ResponseWriter, r *http.Request, secret string) {
	target := strings.TrimPrefix(r.URL.Path, "/mcp/")
	if target == "" || strings.ContainsAny(target, "/%") || r.URL.RawQuery != "" || strings.Contains(r.URL.EscapedPath(), "%") {
		writeError(w, 400, "invalid_request", "Use /mcp/target without query parameters.")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		writeError(w, 405, "method_not_allowed", "Use POST for MCP messages.")
		return
	}
	acceptJSON, acceptSSE := false, false
	for _, value := range r.Header.Values("Accept") {
		for _, item := range strings.Split(value, ",") {
			media, params, err := mime.ParseMediaType(strings.TrimSpace(item))
			if err != nil || params["q"] == "0" {
				continue
			}
			acceptJSON = acceptJSON || media == "application/json"
			acceptSSE = acceptSSE || media == "text/event-stream"
		}
	}
	if !acceptJSON || !acceptSSE {
		writeError(w, 406, "invalid_request", "Accept must include application/json and text/event-stream.")
		return
	}
	wireVersion := r.Header.Get("MCP-Protocol-Version")
	if wireVersion != "" && wireVersion != mcpVersion && wireVersion != "2025-03-26" {
		writeError(w, 400, "invalid_request", "Unsupported MCP protocol version.")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		writeError(w, 415, "invalid_request", "Use unencoded application/json.")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		writeError(w, 413, "request_too_large", "MCP message exceeds the body limit.")
		return
	}
	fields, err := parseObject(body)
	if err != nil {
		rpc(w, nil, nil, -32700, "Use one JSON-RPC object without duplicate keys.")
		return
	}
	var method, protocol string
	_ = json.Unmarshal(fields["method"], &method)
	_ = json.Unmarshal(fields["jsonrpc"], &protocol)
	id := fields["id"]
	if protocol != "2.0" || method == "" || (id != nil && !validRPCID(id)) {
		rpc(w, nil, nil, -32600, "Invalid JSON-RPC request.")
		return
	}
	for key := range fields {
		if key != "jsonrpc" && key != "method" && key != "params" && key != "id" {
			rpc(w, id, nil, -32600, "Unknown JSON-RPC field.")
			return
		}
	}
	params := map[string]json.RawMessage{}
	if raw, ok := fields["params"]; ok {
		params, err = parseObject(raw)
		if err != nil {
			rpc(w, id, nil, -32602, "Parameters must be an object.")
			return
		}
	}
	grant, err := g.store.ResolveGrant(r.Context(), secret)
	if err != nil {
		writeError(w, 500, "storage_error", "Could not read this grant.")
		return
	}
	if method != "tools/call" {
		if grant == nil {
			writeError(w, 401, string(matcher.GrantUnknown), "No grant matches this token.")
			return
		}
		if grant.TargetKind != "mcp_http" || grant.Template.Target != target {
			writeError(w, 403, "tool_not_allowed", "This grant does not allow this MCP target.")
			return
		}
	}
	if id == nil {
		if method == "notifications/initialized" {
			w.WriteHeader(202)
		} else {
			writeError(w, 400, "invalid_request", "Unsupported notification.")
		}
		return
	}
	switch method {
	case "initialize":
		rpc(w, id, map[string]any{"protocolVersion": mcpVersion, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "tokening", "version": version.Version}}, 0, "")
	case "ping":
		rpc(w, id, map[string]any{}, 0, "")
	case "tools/list":
		// The schema is deliberately conservative. The matcher remains authoritative.
		properties := map[string]any{}
		for name, rule := range grant.Template.Args {
			p := map[string]any{}
			if rule.Type != "" {
				p["type"] = rule.Type
			}
			properties[name] = p
		}
		required := []string{}
		for name := range grant.Args {
			required = append(required, name)
		}
		sort.Strings(required)
		rpc(w, id, map[string]any{"tools": []any{map[string]any{"name": grant.Template.Tool, "description": "Scoped by the presented Tokening grant. See GET /grant for bindings and limits.", "inputSchema": map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": grant.Template.AdditionalArgs == "allow"}}}}, 0, "")
	case "tools/call":
		var name string
		if json.Unmarshal(params["name"], &name) != nil || name == "" {
			rpc(w, id, nil, -32602, "Tool name is required.")
			return
		}
		args := map[string]json.RawMessage{}
		if raw, ok := params["arguments"]; ok {
			args, err = parseObject(raw)
			if err != nil {
				rpc(w, id, nil, -32602, "Arguments must be an object.")
				return
			}
		}
		for key := range params {
			if key != "name" && key != "arguments" {
				rpc(w, id, nil, -32602, "Unsupported tool-call parameter.")
				return
			}
		}
		call := matcher.Call{Target: target, Tool: name, Args: args}
		receipt, err := g.store.Consume(r.Context(), secret, call)
		if err != nil {
			writeError(w, 500, "storage_error", "Could not commit authorization.")
			return
		}
		if !receipt.Allowed {
			if receipt.Code == matcher.GrantUnknown {
				writeJSON(w, http.StatusUnauthorized, receipt.Decision)
				return
			}
			text, _ := json.Marshal(receipt.Decision)
			rpc(w, id, toolError(string(text)), 0, "")
			return
		}
		start := time.Now()
		status := 0
		failed := true
		defer func() {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			defer cancel()
			if err := g.store.CompleteUpstream(ctx, receipt, status, time.Since(start), failed); err != nil {
				g.logger.Printf("could not record MCP outcome for grant %s: %v", receipt.Grant, err)
			}
		}()
		result, upstatus, err := g.mcpCall(r.Context(), target, name, args)
		status = upstatus
		if err != nil {
			rpc(w, id, toolError("Upstream MCP request failed. The use remains consumed."), 0, "")
			return
		}
		failed = false
		var outcome struct {
			IsError bool `json:"isError"`
		}
		_ = json.Unmarshal(result, &outcome)
		failed = outcome.IsError
		rpc(w, id, result, 0, "")
	default:
		rpc(w, id, nil, -32601, "Method is not supported by this grant gateway.")
	}
}
func toolError(message string) any {
	return map[string]any{"isError": true, "content": []any{map[string]string{"type": "text", "text": message}}}
}
func validRPCID(raw json.RawMessage) bool {
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return false
	}
	switch v.(type) {
	case string, json.Number:
		return true
	}
	return false
}

func (g *Gateway) mcpCall(ctx context.Context, target, name string, args map[string]json.RawMessage) (json.RawMessage, int, error) {
	info, err := g.store.Target(ctx, target)
	if err != nil || info.Kind != "mcp_http" {
		return nil, 0, errors.New("unavailable target")
	}
	session := ""
	upstreamVersion := "2025-11-25"
	defer func() {
		if session == "" {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(cleanup, "DELETE", info.Destination, nil)
		if err != nil {
			return
		}
		req.Header.Set("Mcp-Session-Id", session)
		req.Header.Set("MCP-Protocol-Version", upstreamVersion)
		plain, err := g.store.Credential(cleanup, target, g.vault)
		if err != nil {
			return
		}
		err = inject(req, info.CredentialType, plain)
		clear(plain)
		if err != nil {
			return
		}
		res, err := g.client.Do(req)
		if err == nil {
			res.Body.Close()
		}
	}()
	send := func(method string, params any, id int) (json.RawMessage, int, error) {
		envelope := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
		if id != 0 {
			envelope["id"] = id
		}
		body, _ := json.Marshal(envelope)
		req, err := http.NewRequestWithContext(ctx, "POST", info.Destination, io.NopCloser(bytes.NewReader(body)))
		if err != nil || req.URL.User != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
			return nil, 0, errors.New("invalid upstream URL")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", upstreamVersion)
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		plain, err := g.store.Credential(ctx, target, g.vault)
		if err != nil {
			return nil, 0, err
		}
		err = inject(req, info.CredentialType, plain)
		clear(plain)
		if err != nil {
			return nil, 0, err
		}
		res, err := g.client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, res.StatusCode, errors.New("upstream status")
		}
		if id == 0 {
			if res.StatusCode != 202 {
				return nil, res.StatusCode, errors.New("notification rejected")
			}
			return nil, res.StatusCode, nil
		}
		if method == "initialize" {
			session = res.Header.Get("Mcp-Session-Id")
			if session != "" && (!validHeaderValue(session) || strings.Contains(session, " ")) {
				return nil, res.StatusCode, errors.New("invalid session")
			}
		}
		media, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
		data, err := io.ReadAll(io.LimitReader(res.Body, MaxBodyBytes+1))
		if err != nil || len(data) > MaxBodyBytes {
			return nil, res.StatusCode, errors.New("upstream response limit")
		}
		if media == "text/event-stream" {
			data, err = sseResponse(data, id)
			if err != nil {
				return nil, res.StatusCode, err
			}
		} else if media != "application/json" {
			return nil, res.StatusCode, errors.New("unsupported response")
		}
		fields, err := parseObject(data)
		if err != nil {
			return nil, res.StatusCode, err
		}
		expected, _ := json.Marshal(id)
		if string(fields["id"]) != string(expected) || string(fields["jsonrpc"]) != `"2.0"` || fields["error"] != nil || fields["result"] == nil {
			return nil, res.StatusCode, errors.New("invalid upstream response")
		}
		return fields["result"], res.StatusCode, nil
	}
	init, status, err := send("initialize", map[string]any{"protocolVersion": upstreamVersion, "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "tokening", "version": version.Version}}, 1)
	if err != nil {
		return nil, status, err
	}
	var initialized struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(init, &initialized) != nil || (initialized.ProtocolVersion != mcpVersion && initialized.ProtocolVersion != "2025-11-25") {
		return nil, status, errors.New("unsupported upstream protocol")
	}
	upstreamVersion = initialized.ProtocolVersion
	if _, status, err = send("notifications/initialized", map[string]any{}, 0); err != nil {
		return nil, status, err
	}
	return send("tools/call", map[string]any{"name": name, "arguments": args}, 2)
}
func sseResponse(data []byte, id int) ([]byte, error) {
	scanner := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})))
	scanner.Split(splitSSELines)
	scanner.Buffer(make([]byte, 4096), MaxBodyBytes+1)
	var event []string
	var found []byte
	flush := func() {
		if len(event) > 0 {
			candidate := []byte(strings.Join(event, "\n"))
			var v struct {
				ID int `json:"id"`
			}
			if json.Unmarshal(candidate, &v) == nil && v.ID == id {
				if found != nil {
					found = []byte("invalid")
				} else {
					found = candidate
				}
			}
		}
		event = nil
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			flush()
		} else if strings.HasPrefix(line, "data:") {
			event = append(event, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	if scanner.Err() != nil || found == nil {
		return nil, errors.New("missing SSE response")
	}
	return found, nil
}

// SSE permits CR, LF and CRLF line endings, independent of the platform.
func splitSSELines(data []byte, atEOF bool) (int, []byte, error) {
	for i, b := range data {
		if b == '\n' {
			return i + 1, data[:i], nil
		}
		if b == '\r' {
			if i+1 == len(data) && !atEOF {
				return 0, nil, nil
			}
			n := 1
			if i+1 < len(data) && data[i+1] == '\n' {
				n = 2
			}
			return i + n, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}
