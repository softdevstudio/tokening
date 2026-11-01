"""Stdio case study: Claude Desktop's view of a filesystem server behind Tokening.

Runs the released tokening binary with an mcp_stdio target that starts the
real filesystem MCP server (npx -y @modelcontextprotocol/server-filesystem)
on a temporary notes folder. A grant is bound to one file. The client side
is `tokening connect`, fed the same newline-delimited JSON-RPC a desktop
client sends. Each server start is counted by a wrapper script, so the
transcript shows that refused calls never started the server.

Usage: python3 run.py /path/to/tokening   (run.sh downloads the release)
"""
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
BIN = os.path.abspath(sys.argv[1])
SERVER_PKG = "@modelcontextprotocol/server-filesystem@2.1.0"
WORK = pathlib.Path(tempfile.mkdtemp(prefix="stdio-case-"))
NOTES = WORK / "notes"
AGENT = "http://127.0.0.1:18180"
ADMIN = "http://127.0.0.1:18181"


def tok(args, env=None, check=True, stdin=None):
    r = subprocess.run([BIN] + args, capture_output=True, text=True, env=env, cwd=WORK, input=stdin)
    if check and r.returncode:
        raise RuntimeError("tokening %s: %s" % (" ".join(args), r.stderr))
    return r


def clean(text):
    return text.replace(str(WORK), "/work")


class Transcript:
    def __init__(self, name, title):
        self.path = HERE / name
        self.lines = ["# " + title, "# Recorded by run.py with %s and %s on %s" % (
            tok(["version"]).stdout.strip(), SERVER_PKG, datetime.now(timezone.utc).strftime("%Y-%m-%d")), ""]

    def note(self, text):
        self.lines += ["# " + l for l in text.splitlines()] + [""]

    def add(self, shown, output, code=None):
        self.lines.append("$ " + clean(shown))
        if output.strip():
            self.lines.append(clean(output.rstrip("\n")))
        if code is not None:
            self.lines.append("(exit %d)" % code)
        self.lines.append("")

    def save(self):
        self.path.write_text("\n".join(self.lines).rstrip() + "\n")


def starts():
    f = WORK / "starts.log"
    return len(f.read_text().splitlines()) if f.exists() else 0


def session(secret, messages):
    """Feed messages to `tokening connect` as a desktop client would."""
    env = dict(os.environ, TOKENING_GRANT=secret)
    env.pop("TOKENING_ADMIN_TOKEN", None)
    lines = "".join(json.dumps(m) + "\n" for m in messages)
    r = subprocess.run([BIN, "connect", AGENT + "/mcp/notes"], input=lines, capture_output=True, text=True, env=env, timeout=180)
    replies = {}
    for line in r.stdout.splitlines():
        m = json.loads(line)
        replies[json.dumps(m.get("id"))] = m
    return r, replies


def text_of(reply):
    if "error" in reply:
        return "JSON-RPC error %d: %s" % (reply["error"]["code"], reply["error"]["message"])
    res = reply["result"]
    if "content" in res:
        t = " ".join(c.get("text", "") for c in res["content"])
        return ("isError: " if res.get("isError") else "") + t
    return json.dumps(res, sort_keys=True)


def main():
    if not shutil.which("npx"):
        sys.exit("npx is needed (Node.js)")
    os.chmod(WORK, 0o700)
    NOTES.mkdir()
    (NOTES / "todo.md").write_text("buy flour\ncall the plumber\n")
    (NOTES / "passwords.md").write_text("bank: hunter2\n")
    (NOTES / "journal").mkdir()
    (NOTES / "journal" / "2026-10-31.md").write_text("private\n")
    # Install the pinned server once (network needed only here), count every
    # server start, then hand over to the installed binary. npx would check
    # the registry on every start, which needs network (and proxy variables
    # the server doesn't inherit) at call time.
    subprocess.run(["npm", "install", "--silent", "--prefix", str(WORK / "server"), SERVER_PKG], check=True, capture_output=True, timeout=300)
    wrapper = WORK / "filesystem-server.sh"
    wrapper.write_text('#!/bin/sh\necho start >> "%s/starts.log"\nexec "%s/server/node_modules/.bin/mcp-server-filesystem" "$@"\n' % (WORK, WORK))
    wrapper.chmod(0o700)

    policy = json.loads((HERE / "policy.json").read_text())
    policy["targets"]["notes"]["command"] = ["sh", str(wrapper), str(NOTES)]
    (WORK / "policy.json").write_text(json.dumps(policy, indent=2))
    (WORK / "vault.key").write_text(tok(["keygen"]).stdout)
    os.chmod(WORK / "vault.key", 0o600)
    admin = secrets.token_hex(24)
    env = dict(os.environ, TOKENING_ADMIN_TOKEN=admin, TOKENING_ADMIN_URL=ADMIN, AWS_SECRET_ACCESS_KEY="must-not-reach-the-server")
    server = subprocess.Popen([BIN, "serve", "--policy", "policy.json", "--db", "tokening.db", "--key-file", "vault.key",
                               "--agent", "127.0.0.1:18180", "--admin", "127.0.0.1:18181"],
                              cwd=WORK, env=env, stdout=subprocess.DEVNULL, stderr=open(WORK / "serve.log", "w"))
    summary = {"tokening": tok(["version"]).stdout.strip(), "server": SERVER_PKG, "client": "tokening connect"}
    try:
        for _ in range(100):
            if tok(["template", "list"], env=env, check=False).returncode == 0:
                break
            if server.poll() is not None:
                raise RuntimeError((WORK / "serve.log").read_text())
            time.sleep(0.1)

        t = Transcript("01-one-file-grant.txt", "Claude Desktop through tokening connect, a grant for one file")
        t.note("The policy: an mcp_stdio target that starts the filesystem server on the notes folder,\nand a template for read_text_file with the path bound at issue time.")
        t.add("cat policy.json", json.dumps(policy, indent=2))
        todo = str(NOTES / "todo.md")
        r = tok(["grant", "issue", "notes.read-one-file", "--bind", "path=" + json.dumps(todo), "--uses", "5", "--ttl", "1h",
                 "--to", "claude-desktop", "--by", "owner", "--reason", "read my todo list"], env=env)
        issued = json.loads(r.stdout)
        secret, grant = issued["secret"], issued["grant"]["id"]
        shown = dict(issued, secret="tkg_(shown once, put in TOKENING_GRANT)")
        t.add("tokening grant issue notes.read-one-file --bind 'path=\"%s\"' --uses 5 --ttl 1h --to claude-desktop --reason \"read my todo list\"" % todo,
              json.dumps(shown, indent=2, sort_keys=True))
        t.note("The client session, as newline-delimited JSON-RPC on the stdin of\n`tokening connect http://127.0.0.1:18180/mcp/notes` (TOKENING_GRANT set).")
        before = starts()
        attempts = [
            ("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "case-study", "version": "1"}}),
            ("tools/list", {}),
            ("tools/call", {"name": "read_text_file", "arguments": {"path": todo}}),
            ("tools/call", {"name": "read_text_file", "arguments": {"path": str(NOTES / "passwords.md")}}),
            ("tools/call", {"name": "read_text_file", "arguments": {"path": str(NOTES / "journal" / ".." / "passwords.md")}}),
            ("tools/call", {"name": "read_text_file", "arguments": {"path": todo, "head": 1}}),
            ("tools/call", {"name": "list_directory", "arguments": {"path": str(NOTES)}}),
            ("tools/call", {"name": "write_file", "arguments": {"path": todo, "content": "nothing to do"}}),
        ]
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": attempts[0][1]},
                {"jsonrpc": "2.0", "method": "notifications/initialized"}]
        msgs += [{"jsonrpc": "2.0", "id": i + 1, "method": m, "params": p} for i, (m, p) in enumerate(attempts) if i > 0]
        # One message at a time, as a client waits for each tool result.
        results = []
        for i, m in enumerate(msgs):
            r, replies = session(secret, [m])
            if "id" not in m:
                continue
            reply = replies.get(json.dumps(m["id"]))
            shown_msg = json.dumps(m)
            out = text_of(reply) if reply else "(no reply) " + r.stderr
            t.add(shown_msg, out)
            results.append({"request": m["method"] + (" " + m["params"].get("name", "") if m["method"] == "tools/call" else ""),
                            "arguments": m["params"].get("arguments"), "reply": out})
        started = starts() - before
        t.note("Server starts during this session: %d (one per allowed call; refused calls start nothing)." % started)
        t.add("cat notes/todo.md notes/passwords.md", (NOTES / "todo.md").read_text() + (NOTES / "passwords.md").read_text())
        t.add("tokening grant inspect " + grant, json.dumps({k: v for k, v in json.loads(tok(["grant", "inspect", grant], env=env).stdout).items()
                                                            if k in ("state", "uses_left", "initial_uses", "decision_count")}, indent=2, sort_keys=True))
        t.save()
        summary["read_session"] = {"server_starts": started, "results": results}

        t = Transcript("02-write-once.txt", "One write, once")
        new = str(NOTES / "shopping.md")
        r = tok(["grant", "issue", "notes.write-one-file", "--bind", "path=" + json.dumps(new), "--uses", "1", "--ttl", "15m",
                 "--to", "claude-desktop", "--by", "owner", "--reason", "start a shopping list"], env=env)
        wsecret = json.loads(r.stdout)["secret"]
        t.add("tokening grant issue notes.write-one-file --bind 'path=\"%s\"' --uses 1 --ttl 15m ..." % new, "(grant issued)")
        before = starts()
        writes = []
        for i, args in enumerate([{"path": new, "content": "flour\neggs\n"}, {"path": new, "content": "overwritten"},
                                  {"path": todo, "content": "overwritten"}]):
            m = {"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call", "params": {"name": "write_file", "arguments": args}}
            r, replies = session(wsecret, [m])
            out = text_of(replies[json.dumps(10 + i)])
            t.add(json.dumps(m), out)
            writes.append(out)
        t.note("Server starts: %d." % (starts() - before))
        t.add("cat notes/shopping.md notes/todo.md", (NOTES / "shopping.md").read_text() + (NOTES / "todo.md").read_text())
        t.save()
        summary["write_session"] = {"server_starts": starts() - before, "replies": writes,
                                    "shopping_md": (NOTES / "shopping.md").read_text(), "todo_md_unchanged": (NOTES / "todo.md").read_text() == "buy flour\ncall the plumber\n"}

        t = Transcript("03-records.txt", "What the operator sees afterwards")
        r = tok(["log", "--export"], env=env)
        rows = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
        t.add("tokening log --export | (one line per decision, shortened)",
              "\n".join("%s %s %s" % (row.get("code", ""), row.get("action", row.get("tool", "")), row.get("reason", ""))[:200] for row in rows if "code" in row))
        for args in (["flight", "verify", "--db", "tokening.db"], ["flight", "replay", "--db", "tokening.db", "--agent", "claude-desktop"]):
            r = tok(args, check=False)
            t.add("tokening " + " ".join(args), r.stdout + r.stderr, r.returncode)
        t.save()
        summary["flight_verify_exit"] = tok(["flight", "verify", "--db", "tokening.db"], check=False).returncode
    except Exception:
        print((WORK / "serve.log").read_text(), file=sys.stderr)
        raise
    finally:
        server.terminate()
        server.wait(timeout=10)
        shutil.rmtree(WORK, ignore_errors=True)
    (HERE / "summary.json").write_text(clean(json.dumps(summary, indent=2, sort_keys=True)) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
