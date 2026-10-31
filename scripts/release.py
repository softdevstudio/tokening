"""Native release packaging, review guard and publication through GITHUB_TOKEN."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import pathlib
import queue
import re
import secrets
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
TARGETS = ('linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64', 'windows-amd64')
REQUIRED = ('TestConsumeSingleUseRace1000', 'TestConsumeCrashRecovery/before-commit', 'TestConsumeCrashRecovery/after-commit', 'TestConsumeCommitFailureRollsBack', 'TestRevocationDuringInFlightHTTP', 'TestHTTPUsesSavedPolicyVersion',
            'TestFlightTamperingIsCaught', 'TestFlightConcurrentWriters', 'TestFlightConcurrentProcesses', 'TestFlightCrashMidWrite', 'TestFlightAppendFailureRollsBackDecision', 'TestFlightRecorderEvidence')


def command(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, text=True, **kwargs).strip()


def version(root=ROOT):
    match = re.search(r'^const Version = "(\d+\.\d+\.\d+)"$', (root / 'internal/version/version.go').read_text(encoding='utf-8'), re.M)
    if not match:
        raise RuntimeError('A plain semantic version constant is needed')
    return match[1]


def source_digest(root=ROOT):
    paths = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    digest = hashlib.sha256()
    roots = {'.go-version', '.gitattributes', '.dockerignore', '.gitignore', 'go.mod', 'go.sum', 'Makefile', 'README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md', 'CHANGELOG.md'}
    for name in sorted(paths):
        if not name or name.startswith('docs/review-'):
            continue
        if name not in roots and not name.startswith(('cmd/', 'internal/', 'demo/', 'scripts/', '.github/workflows/', 'examples/', 'third_party/', 'docs/')):
            continue
        digest.update(name.encode() + b'\0' + hashlib.sha256((root / name).read_bytes()).digest())
    return digest.hexdigest()


def check_review(root=ROOT):
    record = json.loads((root / 'release-readiness.json').read_text(encoding='utf-8'))
    if record.get('version') != version(root) or record.get('status') != 'approved' or record.get('source_sha256') != source_digest(root):
        raise RuntimeError('The release source does not match an approved independent review')
    return record


def output(values):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as destination:
        for key, value in values.items():
            destination.write(f'{key}={value}\n')


def github(path):
    request = urllib.request.Request('https://api.github.com/repos/' + os.environ['GITHUB_REPOSITORY'] + path, headers={'Authorization':'Bearer ' + os.environ['GH_TOKEN'], 'Accept':'application/vnd.github+json', 'User-Agent':'Tokening-release'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def remote_tag_commit(tag):
    ref = github('/git/ref/tags/' + tag)
    if ref is None:
        return None
    obj = ref['object']
    for _ in range(5):
        if obj['type'] == 'commit':
            return obj['sha']
        if obj['type'] != 'tag':
            break
        obj = github('/git/tags/' + obj['sha'])['object']
    raise RuntimeError('Release tag does not resolve to a commit')


def release_state(tag, sha, rebuild):
    tagged = remote_tag_commit(tag)
    existing = github('/releases/tags/' + tag)
    if existing and not existing['draft'] and not rebuild:
        return 'published'
    if tagged is not None and tagged != sha:
        raise RuntimeError('Release tag belongs to another source commit')
    if existing and existing['draft'] and existing['target_commitish'] != sha:
        raise RuntimeError('Existing draft is not bound to this exact source commit')
    return 'resume' if existing else 'new'


def prepare():
    tag, sha = 'v' + version(), command(['git', 'rev-parse', 'HEAD'])
    state = release_state(tag, sha, os.environ.get('REBUILD') == 'true')
    if state == 'published':
        print('Version already published; no release needed.')
        output({'release': 'false'})
        return
    if os.environ.get('RELEASE_EVENT') == 'workflow_run' and command(['git', 'rev-parse', 'origin/main']) != sha:
        print('A newer main commit exists; waiting for its CI.')
        output({'release': 'false'})
        return
    readiness = ROOT / 'release-readiness.json'
    if not readiness.exists() or json.loads(readiness.read_text(encoding='utf-8')).get('status') == 'pending':
        print('Independent review is pending; nothing will be published.')
        output({'release': 'false'})
        return
    check_review()
    output({'release': 'true', 'sha': sha, 'version': version(), 'tag': tag})


def archive_files(binary):
    files = [(binary, binary.name)]
    for name in ('README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md', 'CHANGELOG.md'):
        files.append((ROOT / name, name))
    for directory in ('docs', 'examples', 'third_party'):
        for source in sorted((ROOT / directory).glob('*')):
            if source.is_file() and not source.name.startswith('review-'):
                files.append((source, directory + '/' + source.name))
    files.append((ROOT / 'demo/README.md','demo/README.md'))
    return files


def pack(destination, binary):
    files = archive_files(binary)
    if destination.suffix == '.zip':
        with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for source, name in files:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o100755 if source == binary else 0o100644) << 16
                archive.writestr(info, source.read_bytes())
    else:
        with destination.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w') as archive:
            for source, name in files:
                data = source.read_bytes()
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), 0o755 if source == binary else 0o644, 0
                archive.addfile(info, io.BytesIO(data))


def smoke(binary, log):
    assert command([str(binary), 'version']) == 'tokening ' + version()
    assert 'Tokening' in command([str(binary), 'help'])
    assert 'valid' in command([str(binary), 'check', str(binary.parent / 'examples/wordpress.json')])
    assert len(base64.b64decode(command([str(binary), 'keygen']), validate=True)) == 32
    with tempfile.TemporaryDirectory(prefix='tokening-smoke-') as directory, log.open('w') as diagnostic:
        state = pathlib.Path(directory)
        policy = {'targets': {'wp': {'kind': 'http', 'url': 'http://127.0.0.1:1', 'credential': {'type': 'bearer', 'ref': 'vault:wp'}}}, 'templates': {'edit': {'target': 'wp', 'method': 'PATCH', 'path': '/posts/{id}', 'args': {'id': {'bind': 'required'}}, 'max_uses': 1, 'max_ttl': '15m'}}}
        (state / 'policy.json').write_text(json.dumps(policy))
        env = os.environ.copy()
        env['TOKENING_ADMIN_TOKEN'] = secrets.token_urlsafe(32)
        env['TOKENING_VAULT_KEY'] = base64.b64encode(secrets.token_bytes(32)).decode()
        process = subprocess.Popen([str(binary), 'serve', '--policy', str(state / 'policy.json'), '--db', str(state / 'db'), '--agent', '127.0.0.1:0', '--admin', '127.0.0.1:0'], env=env, stdout=subprocess.PIPE, stderr=diagnostic, text=True)
        lines = queue.Queue()
        def read_lines():
            for line in process.stdout:
                lines.put(line)
        threading.Thread(target=read_lines, daemon=True).start()
        try:
            first, second = lines.get(timeout=15), lines.get(timeout=15)
            if not first.startswith('Agent listener 127.0.0.1:') or not second.startswith('Admin listener 127.0.0.1:'):
                raise RuntimeError('Smoke server did not bind two loopback listeners')
            agent = 'http://' + first.split()[-1]
            env['TOKENING_ADMIN_URL'] = 'http://' + second.split()[-1]
            def cli(*args):
                return json.loads(subprocess.check_output([str(binary), *args], env=env, text=True, timeout=15))
            issued = cli('grant', 'issue', 'edit', '--bind', 'id=2', '--ttl', '1m', '--to', 'smoke-agent', '--reason', 'native archive smoke')
            def request(path, method='GET'):
                req = urllib.request.Request(agent + path, method=method, headers={'Authorization': 'Bearer ' + issued['secret']})
                try:
                    response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    return response.status, json.load(response)
            status, description = request('/grant')
            assert status == 200 and description['uses_left'] == 1
            status, refusal = request('/http/wp/posts/3', 'PATCH')
            assert status == 403 and refusal['code'] == 'arg_mismatch'
            assert cli('grant', 'inspect', issued['grant']['id'])['uses_left'] == 1
            assert cli('grant', 'revoke', issued['grant']['id'])['state'] == 'revoked'
            status, refusal = request('/http/wp/posts/2', 'PATCH')
            assert status == 403 and refusal['code'] == 'grant_revoked'
            exported = subprocess.check_output([str(binary), 'log', '--export'], env=env, text=True, timeout=15)
            assert len(exported.splitlines()) == 2 and issued['secret'] not in exported
            # Issue, two request/decision pairs and the revocation: six chained entries.
            verified = subprocess.check_output([str(binary), 'flight', 'verify', '--db', str(state / 'db')], text=True, timeout=15)
            assert 'Intact: 6 entries' in verified, verified
            replay = subprocess.check_output([str(binary), 'flight', 'replay', '--db', str(state / 'db'), '--agent', 'smoke-agent'], text=True, timeout=15)
            assert 'revoked by' in replay and issued['secret'] not in replay
        finally:
            if process.poll() is None:
                process.terminate() if os.name == 'nt' else process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stdout.close()
            if os.name != 'nt' and process.returncode != 0:
                raise RuntimeError('Unix smoke server did not shut down cleanly')


def record_native_tests(logs):
    # Module downloads and compiler diagnostics are stderr, not JSON events.
    with (logs / 'tests.jsonl').open('w') as recording, (logs / 'test-stderr.log').open('w') as diagnostic:
        result = subprocess.run(['go', 'test', '-count=1', '-json', './...'], cwd=ROOT, stdout=recording, stderr=diagnostic)
    if result.returncode:
        print((logs / 'test-stderr.log').read_text(encoding='utf-8')[-16000:])
        print((logs / 'tests.jsonl').read_text(encoding='utf-8')[-16000:])
        raise RuntimeError('Native tests failed; complete stdout and stderr diagnostics are retained')
    return test_summary(logs / 'tests.jsonl')


def build(target):
    check_review()
    goos, arch = target.split('-')
    if command(['go', 'env', 'GOHOSTOS']) != goos or command(['go', 'env', 'GOHOSTARCH']) != arch:
        raise RuntimeError('Each release binary must be built and tested on its native architecture')
    if command(['go', 'env', 'GOVERSION']) != 'go' + (ROOT / '.go-version').read_text(encoding='utf-8').strip():
        raise RuntimeError('Release toolchain does not match .go-version')
    logs = ROOT / 'test/results/local' / ('release-' + target)
    logs.mkdir(parents=True, exist_ok=True)
    failure_results = record_native_tests(logs)
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='tokening-package-') as directory:
        temporary = pathlib.Path(directory)
        binary = temporary / ('tokening.exe' if goos == 'windows' else 'tokening')
        subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(binary), './cmd/tokening'], cwd=ROOT, check=True)
        destination = dist / ('tokening-' + target + ('.zip' if goos == 'windows' else '.tar.gz'))
        pack(destination, binary)
        extracted = temporary / 'unpacked'
        extracted.mkdir()
        if goos == 'windows':
            with zipfile.ZipFile(destination) as archive:
                archive.extractall(extracted)
        else:
            with tarfile.open(destination) as archive:
                archive.extractall(extracted, filter='data')
        smoke(extracted / binary.name, logs / 'smoke-server.log')
    report = {'target': target, 'version': version(), 'source_commit': command(['git', 'rev-parse', 'HEAD']), 'go_version': command(['go', 'env', 'GOVERSION']), 'archive': destination.name, 'sha256': hashlib.sha256(destination.read_bytes()).hexdigest(), 'native_tests': 'passed', 'archive_smoke': 'passed', 'failure_tests':failure_results}
    (dist / (target + '.json')).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


def test_summary(path):
    outcomes, race, recorder = {}, None, None
    for line in path.read_text(encoding='utf-8').splitlines():
        record = json.loads(line)
        if record.get('Test') and record.get('Action') in ('pass', 'fail', 'skip'):
            outcomes[record['Test']] = record['Action']
        text = record.get('Output', '')
        start = text.find('{"consumer_race":')
        if start >= 0:
            race = json.loads(text[start:].strip())['consumer_race']
        start = text.find('{"flight_recorder":')
        if start >= 0:
            recorder = json.loads(text[start:].strip())['flight_recorder']
    if any(outcomes.get(name) != 'pass' for name in REQUIRED) or 'fail' in outcomes.values() or not race or not recorder:
        raise RuntimeError('Required failure tests, race or flight recorder measurements are missing')
    if recorder.get('tamper_cases', 0) < 1 or recorder['tamper_caught'] != recorder['tamper_cases'] or recorder.get('crash_kills', 0) < 1 or recorder['crash_verified'] != recorder['crash_kills'] or recorder.get('thread_entries', 0) < 1 or recorder.get('process_entries', 0) < 1:
        raise RuntimeError('Flight recorder measurements failed')
    if race.get('runs') != 1000 or race.get('callers_per_run',0) < 2 or race['allowed'] != race['runs'] or race['exhausted'] != race['runs'] or race['remaining_uses'] != 0:
        raise RuntimeError('Single-use race measurements failed')
    return {'required_tests': {name: outcomes[name] for name in REQUIRED}, 'consumer_race': race, 'flight_recorder': recorder}


def latest_allowed(tag, latest):
    if latest is None:
        return True
    current = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)',latest['tag_name'])
    candidate = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)',tag)
    return bool(current and candidate and tuple(map(int,candidate.groups())) >= tuple(map(int,current.groups())))


def publish():
    check_review()
    sha = command(['git', 'rev-parse', 'HEAD'])
    dist, evidence = ROOT / 'dist', ROOT / 'evidence'
    if os.environ.get('RELEASE_EVENT') == 'workflow_run':
        head = json.loads(command(['gh', 'api', 'repos/' + os.environ['GITHUB_REPOSITORY'] + '/git/ref/heads/main']))['object']['sha']
        if head != sha:
            raise RuntimeError('Main changed during the build; wait for its green CI')
    reports = []
    for target in TARGETS:
        report = json.loads((dist / (target + '.json')).read_text(encoding='utf-8'))
        archive = dist / report['archive']
        expected = 'tokening-' + target + ('.zip' if target.startswith('windows') else '.tar.gz')
        if report['archive'] != expected or report['source_commit'] != sha or report['version'] != version() or report['native_tests'] != 'passed' or report['archive_smoke'] != 'passed' or hashlib.sha256(archive.read_bytes()).hexdigest() != report['sha256']:
            raise RuntimeError('Native package evidence does not match the release source')
        reports.append(report)
    checks = {}
    for runner in ('ubuntu-latest', 'macos-latest'):
        checks[runner] = test_summary(evidence / 'tests' / ('check-log-' + runner) / 'tests.jsonl')
    replay = json.loads((evidence / 'demo/replay.json').read_text(encoding='utf-8'))
    browser = json.loads((evidence / 'panel/browser-results.json').read_text(encoding='utf-8'))
    if replay['passed'] is not True or browser['passed'] is not True or browser['offline_network_requests'] != 0 or replay['wordpress']['writes'] != 2 or replay['wordpress']['deletes'] != 0 or replay['agent']['parallel_winners'] != 1 or replay['agent']['isolation'] != 'passed':
        raise RuntimeError('Demo or browser evidence failed')
    shutil.copyfile(evidence / 'demo/replay.html', dist / 'demo-replay.html')
    shutil.copyfile(evidence / 'demo/replay.json', dist / 'demo-results.json')
    shutil.copyfile(evidence / 'demo/decisions.jsonl', dist / 'decisions.jsonl')
    result = {'version': version(), 'source_commit': sha, 'ci_run_id':os.environ.get('EVIDENCE_RUN_ID'), 'release_run_id':os.environ.get('GITHUB_RUN_ID'), 'independent_review': check_review(), 'checks': checks, 'native_builds': reports, 'browser': browser, 'demo': {'writes': replay['wordpress']['writes'], 'deletes': replay['wordpress']['deletes'], 'parallel_winners': replay['agent']['parallel_winners']}}
    (dist / 'test-results.json').write_text(json.dumps(result, indent=2) + '\n')
    names = [report['archive'] for report in reports] + ['demo-replay.html', 'demo-results.json', 'decisions.jsonl', 'test-results.json']
    (dist / 'SHA256SUMS').write_text(''.join(hashlib.sha256((dist / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in sorted(names)))
    names.append('SHA256SUMS')
    tag = 'v' + version()
    state = release_state(tag,sha,True)
    if state == 'new':
        subprocess.run(['gh', 'release', 'create', tag, '--draft', '--target', sha, '--title', 'Tokening ' + tag, '--notes-file', 'CHANGELOG.md'], cwd=ROOT, check=True)
    # Refuse to upload onto a moved or conflicting tag, even after a long build.
    if remote_tag_commit(tag) not in (None,sha):
        raise RuntimeError('Release tag moved before upload')
    subprocess.run(['gh', 'release', 'upload', tag, *[str(dist / name) for name in names], '--clobber'], cwd=ROOT, check=True)
    if remote_tag_commit(tag) not in (None,sha):
        raise RuntimeError('Release tag moved before publication')
    latest = '--latest=true' if latest_allowed(tag,github('/releases/latest')) else '--latest=false'
    subprocess.run(['gh', 'release', 'edit', tag, '--draft=false', '--prerelease=false', latest, '--title', 'Tokening ' + tag, '--notes-file', 'CHANGELOG.md'], cwd=ROOT, check=True)
    print('Published Tokening ' + tag)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('digest', 'prepare', 'build', 'publish'))
    parser.add_argument('--target', choices=TARGETS)
    args = parser.parse_args()
    if args.action == 'digest':
        print(source_digest())
    elif args.action == 'prepare':
        prepare()
    elif args.action == 'build':
        if not args.target:
            parser.error('--target is needed for build')
        build(args.target)
    else:
        publish()
