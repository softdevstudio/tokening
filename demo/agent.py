"""Deterministic agent. Only grant secrets enter this network-isolated process."""
import concurrent.futures
import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request

ENDPOINT = "http://tokening:8080/mcp/demo-wp"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def rpc(secret, method, params, request_id=1):
    envelope = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        envelope["id"] = request_id
    request = urllib.request.Request(ENDPOINT, json.dumps(envelope).encode(), {
        "Authorization": "Bearer " + secret,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-06-18",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=180) as response:
        if response.status == 202:
            return None
        data = json.loads(response.read(1048577))
    if data.get("id") != request_id or "error" in data:
        raise RuntimeError("Invalid MCP response")
    return data["result"]


def call(secret, tool, arguments, request_id=1):
    result = rpc(secret, "tools/call", {"name": tool, "arguments": arguments}, request_id)
    if result.get("isError"):
        try:
            decision = json.loads(result["content"][0]["text"])
        except (KeyError, ValueError, TypeError):
            raise RuntimeError("Upstream tool error, rather than the expected grant decision") from None
        return {"code": decision["code"], "reason": decision["reason"], "grant": decision["grant"]}
    return {"code": "allowed", "reason": "WordPress accepted the scoped edit."}


def isolation():
    if any(name in os.environ for name in ("TOKENING_ADMIN_TOKEN", "TOKENING_VAULT_KEY", "WP_APPLICATION_PASSWORD")):
        raise RuntimeError("An operator credential reached the agent environment")
    for host, port in (("tokening", 8081), ("wordpress", 80), ("db", 3306)):
        try:
            connection = socket.create_connection((host, port), timeout=1)
        except OSError:
            continue
        connection.close()
        raise RuntimeError("Agent can reach an operator or upstream service")


def run(spec):
    isolation()
    main, parallel = spec["main"], spec["parallel"]
    rpc(main, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "tokening-demo", "version": "0.1.1"}})
    rpc(main, "notifications/initialized", {}, None)
    listing = rpc(main, "tools/list", {})
    if [tool["name"] for tool in listing["tools"]] != ["wp_update_post"]:
        raise RuntimeError("Discovery exposed a tool outside the grant")
    steps = [{"step": "tools/list", "tools": ["wp_update_post"]}]
    attempts = [
        ("edit post 2", "wp_update_post", {"id": 2, "title": "Scoped edit"}, "allowed"),
        ("repeat edit", "wp_update_post", {"id": 2, "title": "Scoped edit"}, "grant_exhausted"),
        ("edit post 3", "wp_update_post", {"id": 3, "title": "Wrong post"}, "arg_mismatch"),
        ("delete post 2", "wp_delete_post", {"id": 2}, "tool_not_allowed"),
    ]
    for label, tool, arguments, expected in attempts:
        decision = call(main, tool, arguments)
        if decision["code"] != expected:
            raise RuntimeError("Unexpected decision for " + label + ": " + decision["code"])
        steps.append({"step": label, "tool": tool, "arguments": arguments, **decision})
    barrier = threading.Barrier(2)

    parallel_arguments = {"id": 2, "title": "Parallel edit"}

    def compete(request_id):
        barrier.wait(timeout=5)
        return call(parallel, "wp_update_post", parallel_arguments, request_id)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(compete, value) for value in (10, 11)]
        decisions = [future.result() for future in futures]
    if sorted(decision["code"] for decision in decisions) != ["allowed", "grant_exhausted"]:
        raise RuntimeError("A one-use parallel grant did not have exactly one winner")
    steps.append({"step": "parallel calls", "tool": "wp_update_post", "arguments": parallel_arguments, "decisions": decisions})
    return {"isolation": "passed", "steps": steps, "parallel_winners": 1}


if __name__ == "__main__":
    try:
        result = run(json.load(sys.stdin))
        print(json.dumps(result))
    except Exception as error:
        # Never dump a request or the stdin specification, which contains grants.
        print("Agent demo failed: " + str(error), file=sys.stderr)
        sys.exit(1)
