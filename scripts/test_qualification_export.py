"""Synthetic export-guard tests; no network, credentials or real soaks."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import qualification_export as exporter


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run = self.base / 'private'
        self.run.mkdir()
        self.meta = dict(suite='stateless', command='reproduce', version='1.1.0', sourceDigest='a'*64, binarySHA256='b'*64, platform='linux-amd64', exitCode=0, validationExitCode=0)
        self.report = dict(schemaVersion=1, suite='stateless', command='reproduce', version='1.1.0', sourceDigest='a'*64, binarySha256='b'*64, platform='linux-amd64', interrupted=False, cleanupVerified=True, started='2026-01-01T00:00:00Z', finished='2026-01-01T02:00:00Z', cases=[dict(name='mixed-frames', passes=3, failures=0, repeatedProcessPasses=3, cleanupVerified=True, firstAt='2026-01-01T00:00:00Z', lastAt='2026-01-01T02:00:00Z')], evidence=[])
        self.add('events.jsonl', b'{"event":"synthetic test only"}\n')
        self.add('reproduce-mixed-frames-00001.report.json', b'{"completed":true,"verified":false}\n')
        self.save()

    def add(self, name, data):
        path = self.run / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self.report['evidence'].append(dict(path=name, sha256=hashlib.sha256(data).hexdigest()))

    def save(self):
        (self.run / 'reproduce.run.json').write_text(json.dumps(self.report), encoding='utf-8')

    def reject(self):
        self.save()
        with self.assertRaises((ValueError, UnicodeError)):
            exporter.export_run(self.run, self.base / 'public', self.meta, True)
        self.assertFalse((self.base / 'public').exists())

    def test_exports_only_bound_files_and_exact_bytes(self):
        (self.run / 'private.key').write_text('DO NOT EXPORT', encoding='utf-8')
        exporter.export_run(self.run, self.base / 'public', self.meta, True)
        out = self.base / 'public'
        self.assertFalse((out / 'private.key').exists())
        self.assertEqual((out / 'events.jsonl').read_bytes(), (self.run / 'events.jsonl').read_bytes())
        for line in (out / 'SHA256SUMS').read_text().splitlines():
            expected, name = line.split('  ')
            self.assertEqual(exporter.digest(out / name), expected)
        self.assertTrue(json.loads((out / 'provenance.json').read_text())['qualifying'])

    def test_rejects_unbound_modified_missing_or_duplicate_evidence(self):
        original = copy.deepcopy(self.report)
        for mode in ('hash', 'missing', 'duplicate'):
            with self.subTest(mode=mode):
                self.report = copy.deepcopy(original)
                if mode == 'hash': self.report['evidence'][0]['sha256'] = 'c'*64
                if mode == 'missing': self.report['evidence'][0]['path'] = 'peer.jsonl'
                if mode == 'duplicate': self.report['evidence'].append(self.report['evidence'][0])
                self.reject()

    def test_rejects_path_escape_aliases_and_renamed_private_material(self):
        original = copy.deepcopy(self.report)
        for name in ('../events.jsonl', '/events.jsonl', 'C:/events.jsonl', './events.jsonl', 'a/../events.jsonl', 'a\\events.jsonl', 'fixtures/keylog.txt', 'replaylab.exe'):
            with self.subTest(name=name):
                self.report = copy.deepcopy(original)
                self.report['evidence'][0]['path'] = name
                self.reject()
        for payload in (b'MZbinary', b'\x7fELFbinary', b'-----BEGIN RSA PRIVATE KEY-----', b'-----BEGIN CERTIFICATE-----', b'CLIENT_RANDOM '+b'a'*64+b' '+b'b'*96, b'EXPORTER_SECRET\\t'+b'a'*64+b'\\t'+b'b'*96, b'Authorization: Bearer secret', b'Cookie: session=secret', b'{"ftp.password":"secret"}'):
            with self.subTest(payload=payload[:16]):
                self.report = copy.deepcopy(original)
                self.add('reproduce-mixed-frames-00002.cli.log', payload)
                self.reject()

    def test_rejects_private_content_inside_authoritative_report(self):
        self.report['variables'] = {'ftp.password': 'secret'}
        self.reject()

    def test_rejects_short_failed_unclean_or_unvalidated_success(self):
        original = copy.deepcopy(self.report)
        for change in ('short', 'failed', 'cleanup', 'interrupted', 'pin', 'validation'):
            with self.subTest(change=change):
                self.report = copy.deepcopy(original)
                self.meta['validationExitCode'] = 0
                if change == 'short': self.report['cases'][0]['lastAt'] = '2026-01-01T01:59:59.999999999Z'
                if change == 'failed': self.report['cases'][0]['failures'] = 1
                if change == 'cleanup': self.report['cleanupVerified'] = False
                if change == 'interrupted': self.report['interrupted'] = True
                if change == 'pin': self.report['sourceDigest'] = 'c'*64
                if change == 'validation': self.meta['validationExitCode'] = 1
                self.reject()

    def test_failure_export_excludes_pcaps_and_marks_nonqualifying(self):
        self.add('mixed-frames.pcap', bytes.fromhex('d4c3b2a1') + b'synthetic')
        self.report['cases'][0]['failures'] = 1
        self.save()
        exporter.export_run(self.run, self.base / 'diagnostic', self.meta, False)
        self.assertFalse((self.base / 'diagnostic/mixed-frames.pcap').exists())
        self.assertFalse(json.loads((self.base / 'diagnostic/provenance.json').read_text())['qualifying'])

    def test_redacted_credentials_are_allowed_and_nanoseconds_exact(self):
        exporter.safe_contents(b'{"variables":{"ftp.password":"[REDACTED]"}}', 'report.json')
        self.assertEqual(exporter.timestamp('2026-01-01T02:00:00Z') - exporter.timestamp('2026-01-01T00:00:00.000000001Z'), 7200*10**9-1)

    def test_rejects_symlinked_evidence(self):
        source = self.run / 'events.jsonl'
        outside = self.base / 'outside.jsonl'
        outside.write_bytes(source.read_bytes())
        source.unlink()
        try:
            source.symlink_to(outside)
        except OSError as error:
            self.skipTest('symlink creation unavailable: ' + str(error))
        self.reject()

    def test_failure_diagnostics_also_refuse_secrets(self):
        self.add('reproduce-mixed-frames-00002.cli.log', b'Cookie: session=private')
        self.save()
        with self.assertRaises(ValueError):
            exporter.export_run(self.run, self.base / 'diagnostic', self.meta, False)
        self.assertFalse((self.base / 'diagnostic').exists())

    def test_validator_failure_log_survives_missing_report_with_hash(self):
        log = self.base / 'validation.log'
        payload = b'--- FAIL: TestRecordedStatelessLabTranscript (0.00s)\n    report.json: permission denied\nFAIL\n'
        log.write_bytes(payload)
        (self.base / 'handoff.log').write_bytes(b'raw scratch must be private\n')
        (self.run / 'reproduce.run.json').unlink()
        self.meta['validationExitCode'] = 1
        exporter.failure_diagnostics(self.run, self.base / 'diagnostic', self.meta, log)
        out = self.base / 'diagnostic'
        self.assertEqual((out / 'validation.log').read_bytes(), payload)
        self.assertEqual((out / 'handoff.log').read_bytes(), b'raw scratch must be private\n')
        detail = json.loads((out / 'validation-diagnostic.json').read_text())
        self.assertTrue(detail['retained'])
        self.assertFalse(detail['qualifying'])
        self.assertEqual(detail['sha256'], hashlib.sha256(payload).hexdigest())
        for line in (out / 'SHA256SUMS').read_text().splitlines():
            expected, name = line.split('  ')
            self.assertEqual(exporter.digest(out / name), expected)

    def test_validator_failure_log_is_bounded_and_private_material_omitted(self):
        for label, payload in (('large', b'bounded diagnostic\n' * 20000), ('secret', b'permission denied\n-----BEGIN PRIVATE KEY-----\nprivate-body\n'), ('credential', b'{"ftp.password":"private"}\n')):
            with self.subTest(label=label):
                log = self.base / 'validation.log'
                log.write_bytes(payload)
                out = self.base / label
                exporter.failure_diagnostics(self.run, out, self.meta, log)
                detail = json.loads((out / 'validation-diagnostic.json').read_text())
                if label == 'large':
                    self.assertTrue(detail['truncated'])
                    self.assertLessEqual((out / 'validation.log').stat().st_size, 128 << 10)
                else:
                    self.assertFalse(detail['retained'])
                    self.assertFalse((out / 'validation.log').exists())

    def test_keylog_hidden_in_json_or_pcap_cannot_export(self):
        original = copy.deepcopy(self.report)
        keylog = b'CLIENT_RANDOM ' + b'a'*64 + b' ' + b'b'*96
        samples = [
            ('reproduce-mixed-frames-00002.report.json', b'{"debug":"\\u0043LIENT_RANDOM ' + b'a'*64 + b' ' + b'b'*96 + b'"}'),
            ('mixed-frames.pcap', bytes.fromhex('d4c3b2a1') + b'fixture bytes\x00' + keylog),
        ]
        for name, payload in samples:
            with self.subTest(name=name):
                self.report = copy.deepcopy(original)
                self.add(name, payload)
                self.reject()

    def test_application_capture_fixtures_never_match_export_allowlist(self):
        for name in ('fixtures/http1-tls/fixture.pcap', 'fixtures/http1-tls/fixture.pcapng', 'fixtures/http1-tls/keylog.txt', 'attempts/000001-http1-tls/capture.pcap'):
            self.assertFalse(exporter.allowed(name, 'application', 'live'))

    def test_wire_actual_captures_are_allowed_only_for_packet_suite(self):
        for name in ('wire.actual.pcap', 'wire.actual-1.pcap', 'wire.actual-16.pcap'):
            self.assertTrue(exporter.allowed(name, 'packet', 'live'))
            self.assertFalse(exporter.allowed(name, 'application', 'live'))
            self.assertFalse(exporter.allowed(name, 'stateless', 'reproduce'))
            self.assertFalse(exporter.allowed(name, 'stateless', 'replay'))
        for name in ('wire.actual-0.pcap', 'wire.actual-01.pcap', 'wire.actual--1.pcap',
                     'wire.actual-1.pcapng', 'udp.actual.pcap', 'nested/wire.actual.pcap',
                     '../wire.actual.pcap', 'wire.actual.pcap.key'):
            self.assertFalse(exporter.allowed(name, 'packet', 'live'))
        with self.assertRaises(ValueError):
            exporter.safe_contents(bytes.fromhex('d4c3b2a1') + b'\nPASS private-value\r\n', 'wire.actual.pcap')

    def test_stateless_attempt_progress_keeps_ftp_credentials_blocked(self):
        exporter.safe_contents(b'22 frames, one pass takes 420ms at the chosen rate\nattempt 1 complete (22 frames)\nattempt 2 complete (22 frames)\n', 'reproduce-mixed-frames-00001.cli.log')
        for value in (b'PASS private-value\r\n', b'pass private-value\n', b'pass 1 complete (22 frames)\n'):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    exporter.safe_contents(value, 'reproduce-mixed-frames-00001.cli.log')

    def test_tls_secrets_source_allows_only_exact_public_provenance_enum(self):
        for value in ('none', 'embedded', 'external'):
            for document in ({'tlsSecretsSource': value}, {'outcome': {'tlsSecretsSource': value}}, {'encoded': json.dumps({'tlsSecretsSource': value})}):
                exporter.safe_contents(json.dumps(document).encode(), 'report.json')
            exporter.safe_contents(('status: ' + json.dumps({'tlsSecretsSource': value})).encode(), 'output.txt')
        exporter.safe_contents(b'{"tls\\u0053ecretsSource":"\\u0065mbedded"}', 'report.json')
        for key, value in (('tlsSecretsSource', 'private-value'), ('TLSSecretsSource', 'embedded'), ('tlsSecretsSourceExtra', 'embedded'), ('tlsSecretsSource', None), ('tlsSecretsSource', ''), ('tlsSecretsSource', {'secret': 'value'}), ('tlsSecretsSource', ['embedded'])):
            for document in ({key: value}, {'encoded': json.dumps({key: value})}):
                with self.subTest(key=key, value=value, encoded='encoded' in document):
                    with self.assertRaises(ValueError):
                        exporter.safe_contents(json.dumps(document).encode(), 'report.json')
        with self.assertRaises(ValueError):
            exporter.safe_contents(b'{"tls\\u0053ecretsSource":"private-value"}', 'report.json')

    def test_no_console_cancellation_still_kills_owned_windows_tree(self):
        process = mock.Mock(pid=12345)
        process.poll.side_effect = [None, None]
        process.send_signal.side_effect = OSError('no console')
        # CTRL_BREAK_EVENT is absent on Linux; this tests Windows control flow.
        with mock.patch.object(exporter.signal, 'CTRL_BREAK_EVENT', 1, create=True), mock.patch.object(exporter.subprocess, 'run') as run:
            exporter.stop_owned(process, windows=True)
        self.assertEqual(run.call_args.args[0], ['taskkill', '/PID', '12345', '/T', '/F'])
        process.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)

    def job_args(self):
        return SimpleNamespace(root=self.base, scratch=self.base/'scratch', export=self.base/'public', diagnostic=self.base/'diagnostic', commit='c'*40, source='a'*64, binary='b'*64, version='1.1.0', suite='application', command='live')

    def test_source_pin_mismatch_cannot_start_build_or_traffic(self):
        with mock.patch.object(exporter.subprocess, 'check_output', return_value='c'*40), mock.patch.object(exporter, 'source_digest', return_value='d'*64), mock.patch.object(exporter, 'execute') as execute:
            with self.assertRaisesRegex(ValueError, 'source digest mismatch'):
                exporter.run_job(self.job_args())
        execute.assert_not_called()
        self.assertFalse((self.base/'scratch').exists())

    def test_binary_pin_mismatch_cannot_start_harness_or_traffic(self):
        native = 'windows/amd64' if os.name == 'nt' else 'linux/amd64'
        def build(*_args):
            path = self.base/'scratch'/('livewire.exe' if os.name == 'nt' else 'livewire')
            path.write_bytes(b'different executable')
            return 0
        with mock.patch.object(exporter.subprocess, 'check_output', side_effect=['c'*40, 'go version go1.26.7 '+native]), mock.patch.object(exporter, 'source_digest', return_value='a'*64), mock.patch.object(exporter, 'execute', side_effect=build) as execute:
            with self.assertRaisesRegex(ValueError, 'binary differs'):
                exporter.run_job(self.job_args())
        self.assertEqual(execute.call_count, 1)
        metadata = json.loads((self.base/'diagnostic/failure.json').read_text())
        self.assertFalse(metadata['qualifying'])


@unittest.skipUnless(sys.platform == 'linux', 'native Linux ownership regression')
class RawOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.root = os.geteuid() == 0
        if not self.root and (not shutil.which('sudo') or subprocess.run(['sudo', '-n', 'true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode):
            self.skipTest('requires Linux root orchestration or an ordinary user with passwordless sudo')
        self.uid, self.gid = (65534, 65534) if self.root else (os.getuid(), os.getgid())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        if self.root:
            os.chown(self.base, self.uid, self.gid)

    def privileged(self, argv, **kwargs):
        return subprocess.run(([] if self.root else ['sudo', '-n']) + argv, **kwargs)

    def fixture(self, label, kind='regular'):
        scratch = self.base / label
        scratch.mkdir(mode=0o700)
        if self.root:
            os.chown(scratch, self.uid, self.gid)
        run = scratch / 'run'
        outside = scratch / 'outside'
        outside.write_bytes(b'outside must not change')
        setup = '''import os, pathlib, sys
run, outside, kind = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
run.mkdir()
report = run / 'reproduce-mixed-frames-00001.report.json'
report.write_bytes(b'{"completed":true,"verified":false}\\n')
report.chmod(0o600)
target = run / 'events.jsonl'
if kind == 'symlink': target.symlink_to(outside)
elif kind == 'hardlink': os.link(outside, target)
elif kind == 'fifo': os.mkfifo(target)
elif kind == 'directory': target.mkdir()
elif kind == 'unknown': (run / 'private.key').write_bytes(b'not evidence')
else: target.write_bytes(b'{"event":"synthetic"}\\n')
'''
        self.privileged([sys.executable, '-c', setup, str(run), str(outside), kind], check=True)
        # Only this newly created test directory is removed, after link tests.
        self.addCleanup(self.privileged, [sys.executable, '-c', 'import shutil,sys; shutil.rmtree(sys.argv[1])', str(run)], check=True)
        return run, outside

    def handoff(self, run):
        env = dict(os.environ, SUDO_UID=str(self.uid), SUDO_GID=str(self.gid)) if self.root else None
        return self.privileged([sys.executable, str(Path(exporter.__file__).resolve()), '--handoff-raw', str(run), '--suite', 'stateless', '--command', 'reproduce'], env=env, capture_output=True, text=True)

    def read_as_owner(self, path):
        def become_owner():
            os.setgroups([])
            os.setgid(self.gid)
            os.setuid(self.uid)
        return subprocess.run([sys.executable, '-c', 'import pathlib,sys; sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())', str(path)], preexec_fn=become_owner if self.root else None, capture_output=True)

    def test_root_private_report_becomes_readable_only_to_original_runner(self):
        run, _ = self.fixture('success')
        report = run / 'reproduce-mixed-frames-00001.report.json'
        self.assertEqual(report.stat().st_uid, 0)
        denied = self.read_as_owner(report)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn(b'PermissionError', denied.stderr)
        result = self.handoff(run)
        self.assertEqual(result.returncode, 0, result.stderr)
        read = self.read_as_owner(report)
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertEqual(read.stdout, b'{"completed":true,"verified":false}\n')
        for path, mode in ((run, 0o700), (report, 0o600), (run / 'events.jsonl', 0o600)):
            self.assertEqual(path.stat().st_uid, self.uid)
            self.assertEqual(path.stat().st_gid, self.gid)
            self.assertEqual(path.stat().st_mode & 0o777, mode)

    def test_links_special_entries_and_unknown_files_are_rejected_before_handoff(self):
        for kind in ('symlink', 'hardlink', 'fifo', 'directory', 'unknown'):
            with self.subTest(kind=kind):
                run, outside = self.fixture(kind, kind)
                original = outside.stat()
                result = self.handoff(run)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((run / 'reproduce-mixed-frames-00001.report.json').stat().st_uid, 0)
                self.assertEqual(outside.read_bytes(), b'outside must not change')
                self.assertEqual((outside.stat().st_uid, outside.stat().st_mode), (original.st_uid, original.st_mode))

    def test_nonprivate_parent_and_ancestor_links_are_rejected(self):
        run, _ = self.fixture('parent')
        run.parent.chmod(0o777)
        self.assertNotEqual(self.handoff(run).returncode, 0)
        run.parent.chmod(0o700)
        alias = self.base / 'alias'
        alias.symlink_to(run.parent, target_is_directory=True)
        self.assertNotEqual(self.handoff(alias / 'run').returncode, 0)
        self.assertEqual((run / 'reproduce-mixed-frames-00001.report.json').stat().st_uid, 0)


if __name__ == '__main__':
    unittest.main()
