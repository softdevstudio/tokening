"""Flight recorder case studies, run entirely on this machine.

Starts a stub CMS that speaks MCP on 127.0.0.1:18090, runs the released
tokening binary in front of it, plays a few agent sessions, then exercises
`tokening flight verify | export | replay | head`, including tampering with
copies of the database. Every command and its output is written to the .txt
files next to this script. Nothing here contacts a real site or service.

Usage: python3 run.py /path/to/tokening
(run.sh downloads the latest release binary and calls this.)
"""
import hashlib
import http.server
import json
import os
import pathlib
import secrets
import shutil
import socketserver
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
BIN = os.path.abspath(sys.argv[1])
WORK = pathlib.Path(tempfile.mkdtemp(prefix="flight-cases-"))
DB = WORK / "tokening.db"
AGENT_URL = "http://127.0.0.1:18080"
UPSTREAM_KEY = "stub-cms-key-" + secrets.token_hex(8)

# ---------------------------------------------------------------- stub CMS
POSTS = {3: {"title": "Relase notes", "status": "draft"}, 4: {"title": "Pricing", "status": "draft"},
         7: {"title": "Launch note", "status": "draft"}, 8: {"title": "Unreviewed draft", "status": "draft"}}
UPSTREAM_LOG = []


class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, payload=None, session=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(code)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        if session:
            self.send_header("Mcp-Session-Id", session)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        if self.headers.get("Content-Length"):
            return self.rfile.read(int(self.headers["Content-Length"]))
        data = b""
        while True:  # chunked transfer encoding
            size = int(self.rfile.readline().split(b";")[0], 16)
            if size == 0:
                self.rfile.readline()
                return data
            data += self.rfile.read(size)
            self.rfile.readline()

    def do_DELETE(self):
        self.reply(200)

    def do_POST(self):
        message = json.loads(self.body())
        if self.headers.get("Authorization") != "Bearer " + UPSTREAM_KEY:
            return self.reply(401, {"error": "bad credential"})
        method = message.get("method")
        if method == "initialize":
            return self.reply(200, {"jsonrpc": "2.0", "id": message["id"], "result": {
                "protocolVersion": message["params"]["protocolVersion"], "capabilities": {"tools": {}},
                "serverInfo": {"name": "stub-cms", "version": "1"}}}, session=secrets.token_hex(8))
        if method == "notifications/initialized":
            return self.reply(202)
        if method == "tools/call":
            name, args = message["params"]["name"], message["params"]["arguments"]
            UPSTREAM_LOG.append({"tool": name, "id": args.get("id")})
            post = POSTS[int(args["id"])]
            if name == "publish_post":
                post["status"] = "published"
            else:
                post.update({k: v for k, v in args.items() if k in ("title", "content")})
            return self.reply(200, {"jsonrpc": "2.0", "id": message["id"], "result": {
                "content": [{"type": "text", "text": "post %s saved" % args["id"]}], "isError": False}})
        self.reply(400, {"error": "unsupported"})


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


# ---------------------------------------------------------------- helpers
def run(args, check=True, env=None):
    result = subprocess.run([BIN] + args, capture_output=True, text=True, env=env, cwd=WORK)
    if check and result.returncode:
        raise RuntimeError("tokening %s failed: %s" % (" ".join(args), result.stderr))
    return result


class Transcript:
    def __init__(self, name, title):
        self.path = HERE / name
        self.lines = ["# " + title, "# Recorded by run.py with %s on %s" % (run(["version"]).stdout.strip(),
                                                                          datetime.now(timezone.utc).strftime("%Y-%m-%d")), ""]

    def note(self, text):
        self.lines += ["# " + line for line in text.splitlines()] + [""]

    def cmd(self, args, db=None, shown=None):
        result = run(args, check=False)
        text = (result.stdout + result.stderr).rstrip("\n")
        for path, label in ((str(WORK) + "/", ""),):
            text = text.replace(path, label)
        self.lines.append("$ " + (shown or "tokening " + " ".join(a.replace(str(WORK) + "/", "") for a in args)))
        if text:
            self.lines.append(text)
        self.lines += ["(exit %d)" % result.returncode, ""]
        return result

    def save(self):
        self.path.write_text("\n".join(self.lines).rstrip() + "\n")


def mcp_call(secret, tool, arguments, rpc_id):
    body = json.dumps({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call",
                       "params": {"name": tool, "arguments": arguments}}).encode()
    request = urllib.request.Request(AGENT_URL + "/mcp/cms", data=body, method="POST", headers={
        "Authorization": "Bearer " + secret, "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read())["result"]
    except urllib.error.HTTPError as error:
        return {"tool": tool, "arguments": arguments, "isError": True,
                "text": "HTTP %d %s" % (error.code, error.read().decode().strip())}
    return {"tool": tool, "arguments": arguments, "isError": result.get("isError", False),
            "text": result["content"][0]["text"]}


def tools_list(secret):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    request = urllib.request.Request(AGENT_URL + "/mcp/cms", data=body, method="POST", headers={
        "Authorization": "Bearer " + secret, "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return [tool["name"] for tool in json.loads(response.read())["result"]["tools"]]


def chain_hash(seq, at_ms, kind, agent, grant, body, prev):
    """docs/flight.md, "How entries are chained"."""
    data = b"tokening-flight-v1" + struct.pack(">Q", seq) + struct.pack(">q", at_ms)
    for field in (kind, agent, grant, body):
        raw = field.encode()
        data += struct.pack(">I", len(raw)) + raw
    return hashlib.sha256(data + prev).digest()


def copy_db(name):
    target = WORK / name
    source = sqlite3.connect(DB)
    destination = sqlite3.connect(target)
    source.backup(destination)
    source.close()
    destination.close()
    return target


def stamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- session
def main():
    stub = Server(("127.0.0.1", 18090), Stub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    os.chmod(WORK, 0o700)
    (WORK / "vault.key").write_text(run(["keygen"]).stdout)
    os.chmod(WORK / "vault.key", 0o600)
    admin_token = secrets.token_hex(24)
    env = dict(os.environ, TOKENING_ADMIN_TOKEN=admin_token, TOKENING_ADMIN_URL="http://127.0.0.1:18081")
    shutil.copy(HERE / "policy.json", WORK / "policy.json")
    server = subprocess.Popen([BIN, "serve", "--policy", "policy.json", "--db", "tokening.db", "--key-file", "vault.key",
                               "--agent", "127.0.0.1:18080", "--admin", "127.0.0.1:18081"],
                              cwd=WORK, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    summary = {"tokening": run(["version"]).stdout.strip(), "upstream": "local stub CMS speaking MCP over HTTP on 127.0.0.1"}
    try:
        for attempt in range(100):
            if run(["template", "list"], check=False, env=env).returncode == 0:
                break
            if server.poll() is not None:
                raise RuntimeError("tokening serve exited: " + server.stderr.read().decode())
            time.sleep(0.1)
        cred = WORK / "cms-credential.json"
        cred.write_text(json.dumps({"value": UPSTREAM_KEY}))
        run(["target", "add", "cms", "--cred-file", str(cred)], env=env)
        cred.unlink()

        def issue(template, post, uses, agent, reason):
            out = json.loads(run(["grant", "issue", template, "--bind", "id=%d" % post, "--uses", str(uses), "--ttl", "15m",
                                  "--to", agent, "--by", "ops-maria", "--reason", reason], env=env).stdout)
            return out["grant"]["id"], out["secret"]

        start = datetime.now(timezone.utc).replace(microsecond=0)
        time.sleep(1.1)
        calls = []
        # Scenario 1: single-use publish grant.
        g_pub, s_pub = issue("cms.publish-post", 7, 1, "publisher-bot", "publish the approved launch note")
        listed = tools_list(s_pub)
        calls.append(mcp_call(s_pub, "publish_post", {"id": 8}, 2))
        calls.append(mcp_call(s_pub, "publish_post", {"id": 7}, 3))
        calls.append(mcp_call(s_pub, "publish_post", {"id": 7}, 4))
        # A second agent fixing a typo, with one call out of scope.
        g_edit, s_edit = issue("cms.edit-post-text", 3, 2, "editor-bot", "fix typo in post 3 title")
        calls.append(mcp_call(s_edit, "update_post", {"id": 3, "title": "Release notes"}, 5))
        calls.append(mcp_call(s_edit, "update_post", {"id": 3, "title": "Release notes", "status": "published"}, 6))
        # A grant revoked before use, then tried anyway.
        g_rev, s_rev = issue("cms.edit-post-text", 4, 1, "editor-bot", "update pricing title")
        run(["grant", "revoke", g_rev, "--by", "ops-maria"], env=env)
        calls.append(mcp_call(s_rev, "update_post", {"id": 4, "title": "Pricing 2027"}, 7))
        # A token Tokening never issued.
        calls.append(mcp_call("tkn_not_a_real_grant", "update_post", {"id": 4, "title": "x"}, 8))
        time.sleep(1.1)
        end = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=1)
        summary.update({"grants": {"publish": g_pub, "edit": g_edit, "revoked": g_rev}, "tools_list_for_publish_grant": listed,
                        "agent_calls": calls, "calls_that_reached_upstream": UPSTREAM_LOG, "posts_after": POSTS,
                        "window": [stamp(start), stamp(end)]})

        # ------------------------------------------------ 01 publish grant
        t = Transcript("01-single-use-publish.txt", "Case 1: a single-use publish grant, replayed")
        t.note("publisher-bot got grant %s: publish_post, bound to id 7, one use, 15 minutes.\n"
               "It called tools/list (%s), then publish_post on id 8, on id 7, and on id 7 again.\n"
               "Calls the stub CMS actually received: %s" % (g_pub, ", ".join(listed), json.dumps(UPSTREAM_LOG)))
        t.note("What the agent was told for each call:\n" + "\n".join(
            "%s %s -> %s%s" % (c["tool"], json.dumps(c["arguments"]), "error: " if c["isError"] else "", c["text"].replace("\n", " "))
            for c in calls[:3]))
        t.note("Verify was run while tokening serve was still running.")
        t.cmd(["flight", "verify", "--db", str(DB)])
        t.cmd(["flight", "replay", "--db", str(DB), "--agent", "publisher-bot"])
        t.cmd(["flight", "replay", "--db", str(DB), "--grant", g_pub])
        t.save()

        # ------------------------------------------------ recipes (server still running)
        r = Transcript("05-recipes.txt", "Use examples: each recipe run once against the case study database")
        r.note("Recipe 1: save the head from a job you already have (end of day, deploy, backup).\n"
               "Shown as: tokening flight head --db tokening.db >> heads.txt")
        head = r.cmd(["flight", "head", "--db", str(DB)]).stdout.strip()
        r.cmd(["flight", "verify", "--db", str(DB), "--head", head])
        r.note("An empty heads file gives an empty --head. Since 0.1.4 that is a usage error (exit 2),\n"
               "not a silent skip. Shown as: tokening flight verify --db tokening.db --head \"$(tail -n 1 heads.txt)\"")
        r.cmd(["flight", "verify", "--db", str(DB), "--head", ""],
              shown='tokening flight verify --db tokening.db --head ""')
        summary["saved_head"] = head
    finally:
        server.terminate()
        server.wait(timeout=10)

    # Check the documented hash format against the real database.
    conn = sqlite3.connect(DB)
    rows = conn.execute("SELECT seq, at, kind, agent, grant_id, body, prev, hash FROM flight ORDER BY seq").fetchall()
    conn.close()
    prev = bytes(32)
    matches = 0
    for seq, at, kind, agent, grant, body, row_prev, row_hash in rows:
        if row_prev == prev and chain_hash(seq, at, kind, agent, grant, body, prev) == row_hash:
            matches += 1
        prev = row_hash
    summary["entries"] = len(rows)
    summary["entries_recomputed_from_docs_format"] = matches
    seq_of = {}
    for seq, at, kind, agent, grant, body, _, _ in rows:
        seq_of.setdefault((kind, grant), []).append(seq)
    refused_request = seq_of[("request", g_pub)][0]

    r.note("Recipe 2: verify in CI or before an audit. Exit 0 means intact, 1 means broken.\n"
           "The broken copy here has one decision entry edited (see case 2).")
    tampered = copy_db("tampered.db")
    c = sqlite3.connect(tampered)
    c.executescript("DROP TRIGGER flight_no_update;")
    c.execute("UPDATE flight SET body = replace(body, '\"outcome\":\"refused\"', '\"outcome\":\"allowed\"') WHERE seq = ?",
              (refused_request + 1,))
    c.commit()
    c.close()
    r.cmd(["flight", "verify", "--db", str(DB)])
    r.cmd(["flight", "verify", "--db", str(tampered)])
    r.note("Recipe 3: export one agent's actions for a time window, then check the file.")
    window = WORK / "editor-bot.jsonl"
    r.cmd(["flight", "export", "--db", str(DB), "--agent", "editor-bot", "--since", stamp(start), "--until", stamp(end),
           "--output", str(window)])
    r.lines += ["$ wc -l < editor-bot.jsonl", str(len(window.read_text().splitlines())), ""]
    r.cmd(["flight", "verify", "--file", str(window), "--partial"])
    r.note("Recipe 4: replay one grant after an incident.")
    r.cmd(["flight", "replay", "--db", str(DB), "--grant", g_edit])
    r.note("Recipe 5: what the log never stores. Full export searched for the grant secrets,\n"
           "the upstream key and the argument values the agents sent.")
    full = run(["flight", "export", "--db", str(DB)]).stdout
    probes = {"publish grant secret": s_pub, "edit grant secret": s_edit, "revoked grant secret": s_rev,
              "unknown token": "tkn_not_a_real_grant", "upstream key": UPSTREAM_KEY,
              "title value 'Release notes'": "Release notes", "title value 'Pricing 2027'": "Pricing 2027",
              "status value 'published'": '"published"'}
    found = {label: (value in full) for label, value in probes.items()}
    r.lines += ["$ tokening flight export --db tokening.db > all.jsonl   # %d lines" % len(full.splitlines())]
    r.lines += ["searched for %s: %s" % (label, "FOUND" if hit else "not found") for label, hit in found.items()] + [""]
    r.lines += ["argument names in request entries:"] + sorted({
        ", ".join(json.loads(line)["body"].get("args", [])) for line in full.splitlines()
        if json.loads(line)["kind"] == "request"}) + [""]
    r.save()
    summary["never_stored_search"] = found

    # ------------------------------------------------ 02 edited and deleted rows
    t = Transcript("02-edited-and-deleted-rows.txt", "Case 2: someone edits, then deletes, a row in the database")
    t.note("The refused attempt on post 8 is entries %d (request) and %d (decision).\n"
           "Copy A: the decision's outcome changed from refused to allowed with SQLite after dropping the update trigger.\n"
           "Copy B: both entries deleted after dropping the delete trigger." % (refused_request, refused_request + 1))
    t.lines += ["$ sqlite3 tampered.db \"DROP TRIGGER flight_no_update; UPDATE flight SET body = replace(body, "
                "'\\\"outcome\\\":\\\"refused\\\"', '\\\"outcome\\\":\\\"allowed\\\"') WHERE seq = %d\"" % (refused_request + 1), ""]
    t.cmd(["flight", "verify", "--db", str(tampered)])
    t.cmd(["flight", "replay", "--db", str(tampered), "--agent", "publisher-bot"])
    deleted = copy_db("deleted.db")
    c = sqlite3.connect(deleted)
    c.executescript("DROP TRIGGER flight_no_delete;")
    c.execute("DELETE FROM flight WHERE seq IN (?, ?)", (refused_request, refused_request + 1))
    c.commit()
    c.close()
    t.lines += ["$ sqlite3 deleted.db \"DROP TRIGGER flight_no_delete; DELETE FROM flight WHERE seq IN (%d, %d)\"" %
                (refused_request, refused_request + 1), ""]
    t.cmd(["flight", "verify", "--db", str(deleted)])
    truncated = copy_db("truncated.db")
    c = sqlite3.connect(truncated)
    c.executescript("DROP TRIGGER flight_no_delete;")
    c.execute("DELETE FROM flight WHERE seq > ?", (len(rows) - 3,))
    c.commit()
    c.close()
    t.note("Copy C: the last three entries cut off the end.")
    t.lines += ["$ sqlite3 truncated.db \"DROP TRIGGER flight_no_delete; DELETE FROM flight WHERE seq > %d\"" % (len(rows) - 3), ""]
    t.cmd(["flight", "verify", "--db", str(truncated)])
    t.save()

    # ------------------------------------------------ 03 full rebuild vs saved head
    t = Transcript("03-saved-head-vs-rebuild.txt", "Case 3: a full chain rebuild, caught only by a saved head")
    t.note("Head saved at the end of the session: %s\n"
           "Before the rebuild, run.py recomputed every hash in the real database from the format in docs/flight.md:\n"
           "%d of %d entries matched." % (head, matches, len(rows)))
    rebuilt = copy_db("rebuilt.db")
    c = sqlite3.connect(rebuilt)
    c.executescript("DROP TRIGGER flight_no_update; DROP TRIGGER flight_no_delete;")
    kept = [row for row in rows if row[0] not in (refused_request, refused_request + 1)]
    c.execute("DELETE FROM flight")
    prev = bytes(32)
    for new_seq, (seq, at, kind, agent, grant, body, _, _) in enumerate(kept, 1):
        digest = chain_hash(new_seq, at, kind, agent, grant, body, prev)
        c.execute("INSERT INTO flight (seq, at, kind, agent, grant_id, body, prev, hash) VALUES (?,?,?,?,?,?,?,?)",
                  (new_seq, at, kind, agent, grant, body, prev, digest))
        prev = digest
    c.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'flight'", (len(kept),))
    c.commit()
    c.close()
    t.note("The rebuild: drop both triggers, remove entries %d and %d, renumber the rest, recompute every hash,\n"
           "and reset SQLite's counter to the new last entry (%d)." % (refused_request, refused_request + 1, len(kept)))
    t.cmd(["flight", "verify", "--db", str(rebuilt)])
    t.cmd(["flight", "replay", "--db", str(rebuilt), "--agent", "publisher-bot"])
    t.cmd(["flight", "verify", "--db", str(rebuilt), "--head", head])
    rebuilt2 = copy_db("rebuilt-edit.db")
    c = sqlite3.connect(rebuilt2)
    c.executescript("DROP TRIGGER flight_no_update; DROP TRIGGER flight_no_delete;")
    c.execute("DELETE FROM flight")
    prev = bytes(32)
    for seq, at, kind, agent, grant, body, _, _ in rows:
        if seq == refused_request + 1:
            body = body.replace('"outcome":"refused"', '"outcome":"allowed"')
        digest = chain_hash(seq, at, kind, agent, grant, body, prev)
        c.execute("INSERT INTO flight (seq, at, kind, agent, grant_id, body, prev, hash) VALUES (?,?,?,?,?,?,?,?)",
                  (seq, at, kind, agent, grant, body, prev, digest))
        prev = digest
    c.commit()
    c.close()
    t.note("Second rebuild, same length: entry %d's outcome changed from refused to allowed, then every hash from\n"
           "there on recomputed. Entry numbers and the counter stay as they were." % (refused_request + 1))
    t.cmd(["flight", "verify", "--db", str(rebuilt2)])
    t.cmd(["flight", "verify", "--db", str(rebuilt2), "--head", head])
    t.note("The original database against the same saved head:")
    t.cmd(["flight", "verify", "--db", str(DB), "--head", head])
    t.save()

    # ------------------------------------------------ 04 reviewer export
    t = Transcript("04-reviewer-export.txt", "Case 4: exporting one agent's actions for a reviewer")
    export = HERE / "editor-bot.jsonl"
    if export.exists():
        export.unlink()
    t.cmd(["flight", "export", "--db", str(DB), "--agent", "editor-bot", "--since", stamp(start), "--until", stamp(end),
           "--output", str(export)], shown="tokening flight export --db tokening.db --agent editor-bot --since %s --until %s "
                                           "--output editor-bot.jsonl" % (stamp(start), stamp(end)))
    lines = export.read_text().splitlines()
    t.lines += ["$ wc -l < editor-bot.jsonl", str(len(lines)), ""]
    t.note("The reviewer checks the file on their own machine, with no database:")
    t.cmd(["flight", "verify", "--file", str(export)], shown="tokening flight verify --file editor-bot.jsonl")
    t.cmd(["flight", "verify", "--file", str(export), "--partial"], shown="tokening flight verify --file editor-bot.jsonl --partial")
    t.cmd(["flight", "replay", "--file", str(export)], shown="tokening flight replay --file editor-bot.jsonl")
    edited = WORK / "editor-bot-edited.jsonl"
    edited.write_text("\n".join(lines).replace('"outcome":"refused"', '"outcome":"allowed"', 1) + "\n")
    t.note("Someone edits the file before it reaches the reviewer: one refused outcome becomes allowed.")
    t.cmd(["flight", "verify", "--file", str(edited), "--partial"], shown="tokening flight verify --file editor-bot-edited.jsonl --partial")
    t.save()

    (HERE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    shutil.rmtree(WORK)
    print("Recorded case studies in " + str(HERE))


if __name__ == "__main__":
    main()
