"""Run a pinned synthetic software lab and export only reviewed evidence types.

This is not an exporter for arbitrary user captures. The workflow generates all
traffic with the repository's fixed, synthetic peers. Application fixtures,
certificates, keylogs and binaries are private scratch files and never exported.
The official Go transcript validator must pass before a qualifying export.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import subprocess
import sys
import time

APP_CASES = set("http1 dns-tcp modbus-tcp mqtt311 mqtt5 dnp3 http1-tls tls-handshake dns-tls modbus-tls mqtt311-tls mqtt5-tls dnp3-tls ftp ftps-explicit ftps-implicit ssh".split())
PACKET_CASES = set("dns-udp udp icmp4 icmp6 stateful-tcp transport-tcp wire".split())
HEX = re.compile(r"[0-9a-f]{64}\Z")
SECRET = re.compile(rb"-----BEGIN (?:[^\r\n]*PRIVATE KEY|CERTIFICATE)-----|(?:CLIENT_RANDOM|EXPORTER_SECRET|EARLY_EXPORTER_SECRET|(?:CLIENT|SERVER)_(?:EARLY_|HANDSHAKE_)?TRAFFIC_SECRET(?:_\d+)?)\s+[0-9a-fA-F]{64}\s+[0-9a-fA-F]{32,}|(?:Authorization|Proxy-Authorization|Cookie|Set-Cookie)\s*:\s*[^\s]|(?:^|[\r\n])PASS\s+[^\s]", re.I)
SECRET_KEY = re.compile(r"password|passwd|secret|token|private[_-]?key|api[_-]?key|authorization|cookie|(?:^|[._-])pass(?:$|[._-])", re.I)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def timestamp(value):
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)", value)
    require(match is not None, 'invalid timestamp')
    date = dt.datetime.fromisoformat(match[1] + match[3].replace('Z', '+00:00'))
    delta = date - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    return (delta.days * 86400 + delta.seconds) * 10**9 + int((match[2] or '').ljust(9, '0'))


def source_digest(root):
    suffixes = {'.go', '.html', '.cjs', '.ps1', '.py', '.sh'}
    files = [p for top in ('cmd', 'internal', 'scripts') for p in (root / top).rglob('*') if p.is_file() and p.suffix in suffixes]
    files += [root / name for name in ('go.mod', 'go.sum', 'qualification/corpus.json')]
    result = hashlib.sha256()
    for path in sorted(files, key=lambda p: p.relative_to(root).as_posix()):
        result.update(path.relative_to(root).as_posix().encode() + b'\0')
        result.update(path.read_bytes().replace(b'\r\n', b'\n') + b'\0')
    return result.hexdigest()


def safe_path(root, reference):
    require(isinstance(reference, str) and reference and '\\' not in reference and ':' not in reference, 'invalid evidence path')
    relative = PurePosixPath(reference)
    require(not relative.is_absolute() and relative.as_posix() == reference and '..' not in relative.parts, 'evidence path is not canonical')
    path = root
    for part in relative.parts:
        path /= part
        require(not path.is_symlink() and not getattr(path, 'is_junction', lambda: False)(), 'linked evidence is forbidden')
    require(path.is_file() and path.resolve().is_relative_to(root.resolve()), 'evidence is missing or escapes its run')
    require(path.stat().st_size <= 64 << 20, 'evidence exceeds 64 MiB')
    return path


def allowed(reference, suite, command):
    if suite == 'application':
        if reference == 'transcript.jsonl':
            return True
        match = re.fullmatch(r'attempts/[0-9]{6}-(.+)/(output\.txt|report(?:\.attempt-[1-9][0-9]*)?\.json)', reference)
        return bool(match and match[1] in APP_CASES)
    if reference in {'events.jsonl', 'peer.jsonl', 'peer-process.log'}:
        return True
    cases = PACKET_CASES if suite == 'packet' else {'mixed-frames'}
    if reference in {case + '.pcap' for case in cases}:
        return True
    return any(re.fullmatch(re.escape(command + '-' + case) + r'-[0-9]{5}\.(?:report\.json|cli\.log|firewall\.txt|tcpdump\.log|independent\.pcap|actual\.pcap)', reference) for case in cases)


def inspect_json(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_KEY.search(key):
                require(item in ('', '[REDACTED]', None), 'unredacted credential field')
            inspect_json(item)
    elif isinstance(value, list):
        for item in value:
            inspect_json(item)
    elif isinstance(value, str):
        require(not SECRET.search(value.encode()), 'encoded private material in JSON')


def safe_contents(data, name):
    require(not data.startswith((b'MZ', b'\x7fELF')), 'executable evidence forbidden')
    require(not SECRET.search(data.replace(b'\\t', b' ').replace(b'\\n', b'\n').replace(b'\\r', b'\r')), 'private material in evidence')
    # Check textual credential fields regardless of extension, including a
    # JSON object smuggled into a CLI log or packet body.
    for key, value in re.findall(rb'"([^"\r\n]+)"\s*:\s*"([^"\r\n]*)"', data):
        if SECRET_KEY.search(key.decode('ascii', errors='ignore')):
            require(value in (b'', b'[REDACTED]'), 'unredacted credential content')
    if name.endswith('.pcap'):
        require(data[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'), 'unrecognized PCAP evidence')
        return
    text = data.decode('utf-8-sig')
    require('\x00' not in text, 'binary data in textual evidence')
    if name.endswith('.json'):
        inspect_json(json.loads(text))
    elif name.endswith('.jsonl'):
        for line in text.splitlines():
            inspect_json(json.loads(line))


def write_json(path, value):
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    safe_contents(data, path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)


def checked_report(run, suite, command, version, source, binary, native):
    name = 'report.json' if suite == 'application' else command + '.run.json'
    path = safe_path(run, name)
    data = path.read_bytes()
    safe_contents(data, name)
    report = json.loads(data)
    for key, expected in {'schemaVersion': 1, 'suite': suite, 'command': command, 'version': version, 'sourceDigest': source, 'binarySha256': binary, 'platform': native}.items():
        require(report.get(key) == expected, 'report identity mismatch: ' + key)
    return name, data, report


def export_run(run, output, metadata, qualifying):
    """Fail closed before writing: each exact exported byte is hash-bound.

    On failure, only an authoritative report and its safe bound text/JSON refs
    are eligible. Unbound stdout, fixtures and PCAPs are never failure uploads.
    """
    suite, command = metadata['suite'], metadata['command']
    name, data, report = checked_report(run, suite, command, metadata['version'], metadata['sourceDigest'], metadata['binarySHA256'], metadata['platform'])
    if qualifying:
        require(metadata.get('exitCode') == 0 and metadata.get('validationExitCode') == 0, 'execution or independent validation failed')
        require(report.get('interrupted') is False and report.get('cleanupVerified') is True, 'run interrupted or unclean')
        cases = report['cases']
        expected = APP_CASES if suite == 'application' else PACKET_CASES if suite == 'packet' else {'mixed-frames'}
        require(len(cases) == len(expected) and {c['name'] for c in cases} == expected, 'incomplete matrix')
        require(timestamp(report['finished']) - timestamp(report['started']) >= 7200 * 10**9, 'short run')
        for case in cases:
            require(case['failures'] == 0 and case['passes'] >= 3 and case['repeatedProcessPasses'] == case['passes'] and case['cleanupVerified'] is True, 'case failed or unclean')
            require(timestamp(case['lastAt']) - timestamp(case['firstAt']) >= 7200 * 10**9, 'short case span')
    selected, seen = [(name, data)], set()
    for ref in report['evidence']:
        relative = ref['path']
        require(relative not in seen and allowed(relative, suite, command), 'duplicate or forbidden evidence type')
        seen.add(relative)
        require(HEX.fullmatch(ref['sha256']) is not None, 'malformed evidence hash')
        source = safe_path(run, relative)
        raw = source.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == ref['sha256'], 'evidence hash mismatch')
        safe_contents(raw, relative)
        if qualifying or not relative.endswith('.pcap'):
            selected.append((relative, raw))
    require(('transcript.jsonl' if suite == 'application' else 'events.jsonl') in seen, 'missing bound transcript')
    require(not output.exists(), 'refusing to overwrite export')
    # All path/content/hash checks above finish before any upload tree exists.
    stage = output.with_name(output.name + '.staging')
    stage.mkdir(parents=True, exist_ok=False)
    for relative, raw in selected:
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(raw)
    write_json(stage / 'provenance.json', {**metadata, 'qualifying': qualifying, 'reportSHA256': hashlib.sha256(data).hexdigest(), 'scope': 'Synthetic software peers only; no physical NIC/device qualification. Application fixtures, credentials, keylogs and executables are excluded. Final release validation is separate.'})
    if metadata.get('validationProof'):
        write_json(stage / 'validation.json', metadata['validationProof'])
    lines = [digest(path) + '  ' + path.relative_to(stage).as_posix() for path in sorted(stage.rglob('*')) if path.is_file()]
    (stage / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\n')
    require(not output.exists(), 'export destination appeared during staging')
    stage.rename(output)


def stop_owned(process, windows):
    """Attempt cooperative cleanup; unavailable Windows consoles still stop."""
    if process.poll() is not None:
        return
    signalled = False
    try:
        if windows:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            signalled = True
        else:
            signalled = subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', '-' + str(process.pid)], check=False, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        pass
    if signalled:
        try:
            process.wait(timeout=30)
            return
        except subprocess.TimeoutExpired:
            pass
    try:
        if windows:
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], check=False, timeout=10)
        else:
            subprocess.run(['sudo', '-n', 'kill', '-KILL', '--', '-' + str(process.pid)], check=False, timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)


def execute(argv, root, env, log, timeout):
    """Capture private logs; a timed-out owned process gets a cleanup signal."""
    kwargs = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    with log.open('xb') as stream:
        process = subprocess.Popen(argv, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, **kwargs)
        try:
            started = time.monotonic()
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                try:
                    return process.wait(timeout=min(30, remaining))
                except subprocess.TimeoutExpired:
                    if time.monotonic() - started >= timeout:
                        raise
                    print(now(), log.stem, 'still running; elapsed seconds', int(time.monotonic() - started), flush=True)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            stop_owned(process, os.name == 'nt')
            raise


def run_job(args):
    root, scratch = args.root.resolve(), args.scratch.resolve()
    require(re.fullmatch(r'[0-9a-f]{40}', args.commit) is not None, 'candidate commit must be a full SHA')
    require(HEX.fullmatch(args.source) and HEX.fullmatch(args.binary), 'expected hashes must be lowercase SHA256')
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?', args.version) is not None, 'invalid version')
    require(tuple(map(int, args.version.split('-')[0].split('.'))) >= (1, 1, 0), 'hosted command contract requires version1.1 or newer')
    require((args.suite == 'application' and args.command == 'live') or (args.suite == 'packet' and args.command == 'live') or (args.suite == 'stateless' and args.command in ('reproduce', 'replay')), 'unsupported suite/command')
    native = {'Windows': 'windows-amd64', 'Linux': 'linux-amd64'}[platform.system()]
    require(platform.machine().lower() in ('amd64', 'x86_64'), 'native amd64 required')
    require(native == 'linux-amd64' or args.suite == 'application', 'packet suite requires Linux')
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='', GOAMD64='v1', CGO_ENABLED='0', GOEXPERIMENT='')
    env.pop('GOOS', None); env.pop('GOARCH', None)
    def output(argv): return subprocess.check_output(argv, cwd=root, env=env, text=True).strip()
    require(output(['git', 'rev-parse', 'HEAD']) == args.commit, 'checkout differs from candidate commit')
    require(source_digest(root) == args.source, 'source digest mismatch')
    go_version = output(['go', 'version'])
    require(go_version == 'go version go1.26.7 ' + native.replace('-', '/'), 'native pinned Go1.26.7 required')
    require(not scratch.exists(), 'scratch directory already exists')
    scratch.mkdir(parents=True)
    binary = scratch / ('livewire.exe' if os.name == 'nt' else 'livewire')
    meta = {'schemaVersion': 1, 'started': now(), 'commit': args.commit, 'version': args.version, 'suite': args.suite, 'command': args.command, 'sourceDigest': args.source, 'binarySHA256': args.binary, 'platform': native, 'goVersion': go_version, 'runnerImage': os.getenv('ImageOS', ''), 'runnerImageVersion': os.getenv('ImageVersion', ''), 'kernel': platform.release(), 'githubRunId': os.getenv('GITHUB_RUN_ID', ''), 'githubRunAttempt': os.getenv('GITHUB_RUN_ATTEMPT', ''), 'githubJob': os.getenv('GITHUB_JOB', ''), 'githubRepository': os.getenv('GITHUB_REPOSITORY', ''), 'workflowCommit': os.getenv('GITHUB_WORKFLOW_SHA', '')}
    run = scratch / 'run'
    try:
        flags = '-buildid= -s -w -X github.com/kvmukilan/livewire/internal/buildinfo.Version=' + args.version
        code = execute(['go', 'build', '-buildvcs=false', '-trimpath', '-ldflags', flags, '-o', str(binary), './cmd/livewire'], root, env, scratch / 'build.log', 600)
        require(code == 0 and digest(binary) == args.binary, 'native binary differs from frozen release pin')
        if args.suite == 'application':
            harness = scratch / ('replaylab.exe' if os.name == 'nt' else 'replaylab')
            require(execute(['go', 'build', '-buildvcs=false', '-o', str(harness), './scripts/replaylab'], root, env, scratch / 'harness-build.log', 600) == 0, 'harness build failed')
            argv = [str(harness), '-binary', str(binary), '-source-root', str(root), '-out', str(run), '-command', 'live', '-version', args.version, '-duration', '2h', '-interval', '5s', '-repeat', '3', '-process-timeout', '45s', '-environment', 'GitHub-hosted native ' + native + ' synthetic loopback software peers; no physical-device qualification']
            validation_test, validation_env = 'TestRecordedApplicationLabTranscript', {'LIVEWIRE_APPLICATION_LAB_SMOKE': str(run)}
            meta['harnessSHA256'] = digest(harness)
        else:
            argv = ['sudo', '-n', sys.executable, str(root / 'scripts/replaylab_raw.py'), '--binary', str(binary), '--output', str(run), '--source-digest', args.source, '--version', args.version, '--command', args.command, '--duration', '7200', '--round-gap', '5']
            if args.suite == 'packet':
                argv.append('--netem')
                validation_test, validation_env = 'TestRecordedPacketLabTranscript', {'LIVEWIRE_PACKET_LAB_SMOKE': str(run)}
            else:
                validation_test, validation_env = 'TestRecordedStatelessLabTranscript', {'LIVEWIRE_STATELESS_LAB_SMOKE': str(run), 'LIVEWIRE_STATELESS_LAB_COMMAND': args.command}
        meta['exitCode'] = execute(argv, root, env, scratch / 'runner.log', 8700)
        require(source_digest(root) == args.source and digest(binary) == args.binary, 'source or binary changed during lab')
        meta['validationExitCode'] = execute(['go', 'test', './internal/qualification', '-count=1', '-run', '^' + validation_test + '$', '-timeout=10m', '-v'], root, {**env, **validation_env}, scratch / 'validation.log', 660)
        validation_log = (scratch / 'validation.log').read_text(encoding='utf-8')
        require(re.search(r'^--- PASS: ' + validation_test + r' \(', validation_log, re.M) is not None, 'independent transcript validator did not run and pass')
        meta['validationTest'] = validation_test
        meta['validationLogSHA256'] = digest(scratch / 'validation.log')
        meta['validationProof'] = {'test': validation_test, 'exitCode': meta['validationExitCode'], 'logSHA256': meta['validationLogSHA256'], 'passLine': next(line for line in validation_log.splitlines() if line.startswith('--- PASS: ' + validation_test + ' (')), 'scope': 'Extracted exact successful Go test line; full log remains private. The named test independently validates the retained transcript.'}
        require(source_digest(root) == args.source and digest(binary) == args.binary, 'source or binary changed during validation')
        meta['finished'] = now()
        export_run(run, args.export.resolve(), meta, qualifying=True)
    except (Exception, KeyboardInterrupt) as error:
        meta.update(finished=now(), failureType=type(error).__name__, interrupted=isinstance(error, KeyboardInterrupt), qualifying=False)
        # Error text can contain input/secret data, so only its type is exported
        # unless it is already covered by the bound safe report artifacts.
        diagnostic = args.diagnostic.resolve()
        try:
            export_run(run, diagnostic, meta, qualifying=False)
        except Exception:
            require(not diagnostic.exists(), 'incomplete diagnostic export exists')
            diagnostic.mkdir(parents=True)
            write_json(diagnostic / 'failure.json', meta)
        raise


def main():
    def terminate(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--diagnostic', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--suite', choices=('application', 'packet', 'stateless'), required=True)
    parser.add_argument('--command', choices=('live', 'reproduce', 'replay'), required=True)
    run_job(parser.parse_args())


if __name__ == '__main__':
    main()
