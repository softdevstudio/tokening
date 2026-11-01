// Package stdio runs one MCP tool call against a server that speaks MCP over
// standard input and output. Each call starts the server, initializes it,
// sends the one tools/call, and stops it again: the same one-session-per-call
// model the gateway uses for MCP over HTTP.
//
// The package uses only the standard library. The child never inherits the
// gateway's environment: it gets a short base list (PATH, HOME, temp
// directories, locale and the Windows system variables a process needs) plus
// the variables the target's credential names.
package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ProtocolVersion is the MCP version Tokening asks for. Servers may answer
// with any version in acceptedVersions; tools/call has the same shape in all
// of them.
const ProtocolVersion = "2025-06-18"

var acceptedVersions = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true, "2025-11-25": true}

// DefaultTimeout bounds one whole call: start, initialize and tools/call.
// Servers started through npx or uvx can take a few seconds on first run.
const DefaultTimeout = 60 * time.Second

// DefaultMaxLine bounds one JSON-RPC message from the server.
const DefaultMaxLine = 4 << 20

// Options describe one call.
type Options struct {
	// Command is the server's program and arguments, as in the policy.
	Command []string
	// Env holds the credential's variables. Validate them with CheckEnv.
	Env map[string]string
	// Dir is the working directory; empty means the gateway's.
	Dir           string
	Timeout       time.Duration
	MaxLine       int
	ClientName    string
	ClientVersion string
}

// RPCError is a JSON-RPC error the server returned for the tool call.
type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string { return fmt.Sprintf("server error %d: %s", e.Code, e.Message) }

var (
	ErrStart    = errors.New("could not start the stdio server")
	ErrTimeout  = errors.New("the stdio server did not answer in time")
	ErrExited   = errors.New("the stdio server exited before answering")
	ErrProtocol = errors.New("the stdio server broke the MCP protocol")
	ErrTooLarge = errors.New("a message from the stdio server exceeded the size limit")
)

// baseEnv are the variables a child gets from the gateway's own environment,
// when they are set. Nothing else is inherited.
var baseEnv = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
	// Windows: a process can't start or find its files without these.
	"SystemRoot", "SystemDrive", "windir", "PATHEXT", "ComSpec", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
	"ProgramData", "ProgramFiles", "ProgramFiles(x86)", "CommonProgramFiles", "HOMEDRIVE", "HOMEPATH",
	"NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
}

var envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// MaxEnvBytes bounds the credential's variables together.
const MaxEnvBytes = 64 << 10

// CheckEnv validates a credential's variables: upper-case names, none from
// the base list or starting with TOKENING_, values without NUL bytes.
func CheckEnv(env map[string]string) error {
	total := 0
	for name, value := range env {
		if !envName.MatchString(name) {
			return fmt.Errorf("variable names use A-Z, 0-9 and _, and don't start with a digit")
		}
		if strings.HasPrefix(name, "TOKENING_") {
			return fmt.Errorf("TOKENING_ variables can't be passed to a stdio server")
		}
		for _, b := range baseEnv {
			if strings.EqualFold(name, b) {
				return fmt.Errorf("%s comes from the gateway's environment and can't be set by a credential", name)
			}
		}
		if strings.ContainsRune(value, 0) {
			return fmt.Errorf("variable values can't contain NUL")
		}
		total += len(name) + len(value) + 2
	}
	if total > MaxEnvBytes {
		return fmt.Errorf("credential variables exceed %d bytes", MaxEnvBytes)
	}
	return nil
}

// ChildEnv is the environment a child gets: the base list from parent (a
// list of NAME=value, as from os.Environ) plus the credential's variables.
func ChildEnv(parent []string, credential map[string]string) []string {
	var out []string
	for _, kv := range parent {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		for _, b := range baseEnv {
			// Windows names are case-insensitive (Path, PATH).
			if strings.EqualFold(name, b) {
				out = append(out, kv)
				break
			}
		}
	}
	names := make([]string, 0, len(credential))
	for name := range credential {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, name+"="+credential[name])
	}
	return out
}

// Call starts the server, runs one tools/call and stops the server. It
// returns the call's result object.
func Call(ctx context.Context, opt Options, tool string, args map[string]json.RawMessage) (json.RawMessage, error) {
	if len(opt.Command) == 0 || opt.Command[0] == "" {
		return nil, fmt.Errorf("%w: no command", ErrStart)
	}
	if err := CheckEnv(opt.Env); err != nil {
		return nil, err
	}
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	if opt.MaxLine <= 0 {
		opt.MaxLine = DefaultMaxLine
	}
	if opt.ClientName == "" {
		opt.ClientName = "tokening"
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	cmd := exec.Command(opt.Command[0], opt.Command[1:]...)
	cmd.Env = ChildEnv(os.Environ(), opt.Env)
	cmd.Dir = opt.Dir
	// After the server exits, wait at most this long for a child of its own
	// that still holds stderr open.
	cmd.WaitDelay = time.Second
	grp := newGroup(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStart, err)
	}
	// A pipe of our own: cmd.Wait closes a StdoutPipe as soon as the process
	// exits, which can lose the reply of a server that answers and quits.
	stdout, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStart, err)
	}
	defer stdout.Close()
	cmd.Stdout = pw
	stderr := &tail{max: 2048}
	cmd.Stderr = stderr
	err = cmd.Start()
	pw.Close()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("%w: %v", ErrStart, err)
	}
	defer grp.close()
	if err := grp.attach(); err != nil {
		grp.kill()
		stdin.Close()
		cmd.Wait()
		return nil, fmt.Errorf("%w: could not contain the server's processes: %v", ErrStart, err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	defer func() {
		// Close stdin so a well-behaved server exits on its own, give it a
		// moment, then stop it and anything it started.
		stdin.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		grp.kill()
		<-done
	}()
	// The deadline must hold even while a write to a server that stopped
	// reading is blocked: when it passes, close stdin and stop the server,
	// which unblocks the write and the reads.
	stopWatch := context.AfterFunc(ctx, func() {
		stdin.Close()
		grp.kill()
	})
	defer stopWatch()

	s := &session{in: stdin, out: bufio.NewReaderSize(stdout, 64<<10), max: opt.MaxLine, msgs: make(chan message), errs: make(chan error, 1), stop: make(chan struct{})}
	defer close(s.stop)
	go s.read()

	fail := func(err error) (json.RawMessage, error) {
		// The deadline watcher kills the server, so a timeout can look like
		// an exit or a failed write: check the deadline first.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w%s", ErrTimeout, stderr.note())
		}
		select {
		case <-done:
			if errors.Is(err, ErrExited) || errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%w (%v)%s", ErrExited, waitErr, stderr.note())
			}
		default:
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w%s", ErrTimeout, stderr.note())
		}
		return nil, err
	}

	init, err := s.request(ctx, 1, "initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": opt.ClientName, "version": opt.ClientVersion},
	})
	if err != nil {
		return fail(err)
	}
	var initialized struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if json.Unmarshal(init, &initialized) != nil || !acceptedVersions[initialized.ProtocolVersion] {
		return fail(fmt.Errorf("%w: unsupported protocol version", ErrProtocol))
	}
	if err := s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return fail(err)
	}
	if args == nil {
		// Servers expect an object; nil would be sent as null.
		args = map[string]json.RawMessage{}
	}
	result, err := s.request(ctx, 2, "tools/call", map[string]any{"name": tool, "arguments": args})
	if err != nil {
		return fail(err)
	}
	return result, nil
}

type message struct {
	fields map[string]json.RawMessage
}

type session struct {
	in   io.Writer
	out  *bufio.Reader
	max  int
	mu   sync.Mutex
	msgs chan message
	errs chan error
	stop chan struct{}
}

func (s *session) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.in.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("%w: %v", ErrExited, err)
	}
	return nil
}

// read turns stdout into messages until it ends or breaks a rule.
func (s *session) read() {
	for {
		line, err := readLine(s.out, s.max)
		if err != nil {
			s.errs <- err
			return
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		fields, err := object(line)
		if err != nil {
			s.errs <- fmt.Errorf("%w: a line that isn't one JSON object", ErrProtocol)
			return
		}
		select {
		case s.msgs <- message{fields}:
		case <-s.stop:
			return
		}
	}
}

// request sends one request and waits for its response. Requests the server
// sends meanwhile get a "method not found" error; notifications are skipped.
func (s *session) request(ctx context.Context, id int, method string, params any) (json.RawMessage, error) {
	if err := s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, err
	}
	want, _ := json.Marshal(id)
	for {
		select {
		case <-ctx.Done():
			return nil, ErrTimeout
		case err := <-s.errs:
			if errors.Is(err, io.EOF) {
				return nil, ErrExited
			}
			return nil, err
		case m := <-s.msgs:
			f := m.fields
			if string(f["jsonrpc"]) != `"2.0"` {
				return nil, fmt.Errorf("%w: not JSON-RPC 2.0", ErrProtocol)
			}
			if _, isMethod := f["method"]; isMethod {
				if id, hasID := f["id"]; hasID {
					if err := s.send(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32601, "message": "Tokening does not answer requests from the server."}}); err != nil {
						return nil, err
					}
				}
				continue
			}
			if string(f["id"]) != string(want) {
				// A response to something we never sent.
				return nil, fmt.Errorf("%w: a response with an unknown id", ErrProtocol)
			}
			if raw, ok := f["error"]; ok {
				var e struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				}
				if json.Unmarshal(raw, &e) != nil {
					return nil, fmt.Errorf("%w: a malformed error", ErrProtocol)
				}
				return nil, &RPCError{Code: e.Code, Message: e.Message}
			}
			result, ok := f["result"]
			if !ok {
				return nil, fmt.Errorf("%w: a response without a result", ErrProtocol)
			}
			if _, err := object(result); err != nil {
				return nil, fmt.Errorf("%w: a result that isn't an object", ErrProtocol)
			}
			return result, nil
		}
	}
}

// readLine reads one newline-terminated line of at most max bytes.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > max+1 {
			return nil, ErrTooLarge
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

// object decodes one JSON object and rejects duplicate keys, the same way
// the gateway reads agent messages.
func object(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := t.(string)
		if !ok {
			return nil, errors.New("bad key")
		}
		if _, dup := out[key]; dup {
			return nil, errors.New("duplicate key")
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return out, nil
}

// tail keeps the last bytes the server wrote to stderr, for the operator's
// log. It never reaches the agent.
type tail struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tail) note() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := strings.TrimSpace(string(t.buf))
	if s == "" {
		return ""
	}
	return "; server stderr ends: " + strings.ReplaceAll(s, "\n", " | ")
}

// ParseCredential reads an env credential: {"env": {"NAME": "value"}}. The
// object may be empty for a server that needs no secret.
func ParseCredential(plain []byte) (map[string]string, error) {
	fields, err := object(plain)
	if err != nil {
		return nil, errors.New("an env credential is one JSON object")
	}
	raw, ok := fields["env"]
	if !ok || len(fields) != 1 {
		return nil, errors.New(`an env credential has one field, "env"`)
	}
	vars, err := object(raw)
	if err != nil {
		return nil, errors.New(`"env" is an object of names and string values`)
	}
	out := make(map[string]string, len(vars))
	for name, v := range vars {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, fmt.Errorf("%s: values are strings", name)
		}
		out[name] = s
	}
	if err := CheckEnv(out); err != nil {
		return nil, err
	}
	return out, nil
}
