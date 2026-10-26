"""Operator orchestration for a fresh disposable Docker project, never a live site."""
import argparse
import json
import pathlib
import secrets
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
RESULTS = ROOT.parent / "test/results/local/demo"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="keep this isolated Docker project after the run")
    options = parser.parse_args()
    if not shutil.which("docker"):
        raise RuntimeError("Docker with Compose v2 is needed. No site was contacted.")
    project = "tokening-demo-" + secrets.token_hex(4)
    compose = ["docker", "compose", "-p", project, "-f", str(ROOT / "docker-compose.yml")]
    RESULTS.mkdir(parents=True, exist_ok=True)

    def execute(args, payload=None, timeout=600):
        result = subprocess.run(compose + args, input=payload, text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            # Commands never contain credentials. Stdin and successful issuance replies are not logged.
            raise RuntimeError("Docker command failed: " + " ".join(args[:4]) + "\n" + result.stderr[-12000:])
        return result.stdout

    def admin(*args):
        return execute(["exec", "-T", "tokening", "sh", "-ec", 'export TOKENING_ADMIN_TOKEN="$(cat /secrets/admin.token)"; exec tokening "$@"', "sh", *args], timeout=30)

    started = False
    try:
        started = True
        execute(["up", "-d", "--build", "tokening"])
        for attempt in range(60):
            try:
                admin("template", "list")
                break
            except RuntimeError:
                if attempt == 59:
                    raise
                time.sleep(.5)
        admin("target", "add", "demo-wp", "--cred-file", "/secrets/wordpress.json")
        issued = [json.loads(admin("grant", "issue", "wp.edit-post-text", "--bind", "id=2", "--uses", "1", "--ttl", "15m", "--to", "demo-agent", "--by", "demo-operator", "--reason", reason)) for reason in ("edit one post once", "parallel single-use check")]
        before = json.loads(execute(["exec", "-T", "wordpress", "php", "/opt/tokening/snapshot.php"], timeout=30))
        specification = json.dumps({"main": issued[0]["secret"], "parallel": issued[1]["secret"]})
        agent = json.loads(execute(["--profile", "agent", "run", "--rm", "-T", "--no-deps", "agent"], specification, timeout=240))
        wordpress = json.loads(execute(["exec", "-T", "wordpress", "php", "/opt/tokening/verify.php"], timeout=30))
        wordpress["before"] = before
        audit_text = admin("log", "--export")
        audit = [json.loads(line) for line in audit_text.splitlines()]
        authorizations = [row for row in audit if row["authorization_id"] is None and row["code"] == "allowed"]
        completions = [row for row in audit if row["authorization_id"] is not None]
        refusals = [row for row in audit if row["outcome"] == "refused"]
        if len(authorizations) != 2 or len(completions) != 2 or len(refusals) != 4 or any(row["code"] != "allowed" for row in completions):
            raise RuntimeError("Audit records do not match the expected two writes and four refusals")
        grants = [json.loads(admin("grant", "inspect", grant["grant"]["id"])) for grant in issued]
        if any(grant["state"] != "exhausted" or grant["uses_left"] != 0 for grant in grants):
            raise RuntimeError("A demo grant was not exhausted")
        result = {"schema": 1, "passed": True, "agent": agent, "wordpress": wordpress, "grants": grants, "audit": audit}
        serialized = json.dumps(result, indent=2)
        # Check actual generated secrets, not only their expected key names.
        for grant in issued:
            if grant["secret"] in serialized or grant["secret"] in audit_text:
                raise RuntimeError("A grant secret reached a replay artifact")
        # Publish only the secret-free verified snapshot, then render the shared UI offline.
        execute(["exec", "-T", "tokening", "sh", "-ec", "umask 077; cat > /state/demo-replay.tmp; mv /state/demo-replay.tmp /state/demo-replay.json"], serialized, timeout=30)
        html = execute(["exec", "-T", "tokening", "tokening", "replay", "--input", "/state/demo-replay.json"], timeout=30)
        if any(grant["secret"] in html for grant in issued):
            raise RuntimeError("A grant secret reached the HTML replay")
        (RESULTS / "replay.html").write_text(html)
        (RESULTS / "replay.json").write_text(serialized + "\n")
        (RESULTS / "decisions.jsonl").write_text(audit_text)
        print("Docker WordPress demo passed: discovery, one edit, three refusals, one parallel winner, and isolated agent networking.")
        print("Replay: " + str(RESULTS / "replay.json"))
    finally:
        if started:
            logs = subprocess.run(compose + ["logs", "--no-color"], capture_output=True, text=True, timeout=30)
            (RESULTS / "compose.log").write_text(logs.stdout + logs.stderr)
            if options.keep:
                print("Kept Docker project " + project + ". Clean up with: " + " ".join(compose) + " down -v", file=sys.stderr)
            else:
                subprocess.run(compose + ["down", "-v", "--remove-orphans"], check=True, timeout=120)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Demo failed: " + str(error), file=sys.stderr)
        sys.exit(1)
