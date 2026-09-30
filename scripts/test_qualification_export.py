"""Synthetic export-guard tests; no network, credentials or real soaks."""
import copy
import hashlib
import json
import os
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
