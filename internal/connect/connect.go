// Package connect relays an MCP client that speaks stdio (Claude Desktop and
// most local agents launch servers as commands) to a Tokening gateway's
// /mcp/{target} endpoint. Each newline-delimited JSON-RPC message from stdin
// is posted with the grant as its bearer token, and each reply is written
// back to stdout as one line.
//
// The relay holds only the grant secret. It doesn't follow redirects or use
// environment proxies, and it turns HTTP refusals into JSON-RPC errors that
// carry Tokening's readable reason.
package connect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GrantEnv names the variable that holds the grant secret.
const GrantEnv = "TOKENING_GRANT"

// MaxMessage bounds one message in either direction.
const MaxMessage = 4 << 20

// Options configure a relay.
type Options struct {
	// URL is the gateway's MCP endpoint, http(s)://host:port/mcp/target.
	URL   string
	Grant string
	// Client is used for requests; nil means a client that doesn't follow
	// redirects or use proxies, with a two-minute timeout per message.
	Client *http.Client
	// Log gets one line per transport problem. Nil discards.
	Log io.Writer
}

// CheckURL accepts an http or https URL whose path is /mcp/<target>, with
// no credentials, query or fragment.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("the gateway URL must be http(s)://host:port/mcp/<target>")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the gateway URL can't carry credentials, a query or a fragment; the grant goes in " + GrantEnv)
	}
	target, ok := strings.CutPrefix(u.Path, "/mcp/")
	if !ok || target == "" || strings.Contains(target, "/") {
		return errors.New("the gateway URL's path must be /mcp/<target>")
	}
	return nil
}

// Run relays messages from in to the gateway and replies to out until in
// ends. It returns nil at the end of input.
func Run(ctx context.Context, opt Options, in io.Reader, out io.Writer) error {
	if err := CheckURL(opt.URL); err != nil {
		return err
	}
	if strings.TrimSpace(opt.Grant) == "" {
		return fmt.Errorf("set %s to the grant secret", GrantEnv)
	}
	if strings.ContainsAny(opt.Grant, " \t\r\n") {
		return fmt.Errorf("%s holds spaces or line breaks; it should be the grant secret only", GrantEnv)
	}
	client := opt.Client
	if client == nil {
		client = &http.Client{
			Timeout:       2 * time.Minute,
			Transport:     &http.Transport{Proxy: nil, DisableCompression: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	var logMu sync.Mutex
	logf := func(format string, args ...any) {
		if opt.Log != nil {
			logMu.Lock()
			defer logMu.Unlock()
			fmt.Fprintf(opt.Log, "tokening connect: "+format+"\n", args...)
		}
	}
	var (
		writeMu sync.Mutex
		wg      sync.WaitGroup
		slots   = make(chan struct{}, 8)
	)
	reply := func(b []byte) {
		if b == nil {
			return
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		out.Write(append(compact(b), '\n'))
	}
	r := bufio.NewReaderSize(in, 64<<10)
	for {
		line, err := readLine(r)
		if errors.Is(err, errTooLarge) {
			logf("a message from the client exceeded %d bytes and was dropped", MaxMessage)
			reply(rpcError(nil, -32600, "Message too large for the Tokening relay."))
			continue
		}
		if err != nil {
			break
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		id, isRequest := requestID(line)
		slots <- struct{}{}
		wg.Add(1)
		go func(msg []byte) {
			defer wg.Done()
			defer func() { <-slots }()
			res, err := post(ctx, client, opt, msg)
			switch {
			case err != nil:
				logf("%v", err)
				if isRequest {
					reply(rpcError(id, -32000, "The Tokening gateway could not be reached."))
				}
			case res != nil:
				reply(res.body(id, isRequest))
			}
		}(append([]byte(nil), line...))
	}
	wg.Wait()
	return nil
}

var errTooLarge = errors.New("message too large")

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > MaxMessage+1 {
			// Skip the rest of this line.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			return nil, errTooLarge
		}
		line = append(line, part...)
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(bytes.TrimSpace(line)) > 0:
			return line, nil
		default:
			return nil, err
		}
	}
}

// requestID returns the message's id when it is a request (it has a method
// and an id). Responses and notifications get no reply from the relay.
func requestID(msg []byte) (json.RawMessage, bool) {
	var m struct {
		ID     json.RawMessage `json:"id"`
		Method *string         `json:"method"`
	}
	if json.Unmarshal(msg, &m) != nil || m.Method == nil || len(m.ID) == 0 || string(m.ID) == "null" {
		return nil, false
	}
	return m.ID, true
}

type response struct {
	status int
	media  string
	data   []byte
}

func post(ctx context.Context, client *http.Client, opt Options, msg []byte) (*response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", opt.URL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+opt.Grant)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := client.Do(req)
	if err != nil {
		// Don't repeat the URL's error text verbatim: it can't hold the grant,
		// but keep the line short.
		return nil, fmt.Errorf("gateway request failed: %v", errors.Unwrap(err))
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, MaxMessage+1))
	if err != nil || len(data) > MaxMessage {
		return nil, errors.New("gateway reply unreadable or too large")
	}
	if res.StatusCode == http.StatusAccepted {
		return nil, nil
	}
	media, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	return &response{status: res.StatusCode, media: media, data: data}, nil
}

// body turns a gateway reply into the line to write. JSON-RPC replies pass
// through; Tokening's HTTP refusals ({"code","reason"}) become JSON-RPC
// errors for requests and are dropped for notifications.
func (r *response) body(id json.RawMessage, isRequest bool) []byte {
	data := r.data
	if r.media == "text/event-stream" {
		data = sseData(data)
	}
	if r.status == 200 && json.Valid(data) {
		var m map[string]json.RawMessage
		if json.Unmarshal(data, &m) == nil && m["jsonrpc"] != nil {
			return data
		}
	}
	if !isRequest {
		return nil
	}
	var refusal struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(data, &refusal) == nil && refusal.Reason != "" {
		return rpcError(id, -32001, fmt.Sprintf("Tokening refused (%s): %s", refusal.Code, refusal.Reason))
	}
	return rpcError(id, -32000, fmt.Sprintf("The Tokening gateway answered HTTP %d.", r.status))
}

func sseData(b []byte) []byte {
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if d, ok := strings.CutPrefix(l, "data:"); ok {
			lines = append(lines, strings.TrimPrefix(d, " "))
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func rpcError(id json.RawMessage, code int, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
	return b
}

// compact keeps each reply on one line, as stdio MCP needs.
func compact(b []byte) []byte {
	var buf bytes.Buffer
	if json.Compact(&buf, b) == nil {
		return buf.Bytes()
	}
	return bytes.ReplaceAll(b, []byte("\n"), []byte(" "))
}
