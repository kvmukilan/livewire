from pathlib import Path
import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
import qualification as q

class QualificationGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        proof = self.base / 'proof.txt'
        proof.write_text('Synthetic validator fixture; not actual qualification')
        self.evidence = [{'path': proof.name, 'sha256': q.sha(proof)}]
        self.doc = q.template()
        self.doc.update(sourceDigest='test', blockingFindings=[])
        for p in self.doc['platforms'].values():
            for field in ('os','driver','nic','dut','firmware','binarySha256'):
                p[field] = 'test'
            for scenario in q.SCENARIOS:
                p['scenarios'][scenario] = [dict(passed=True, cleanupVerified=True, expectedResult='expected', observedResult='observed', cancelSeconds=0.1, evidence=self.evidence) for _ in range(3)]
            p['soak'] = dict(seconds=7200, passed=True, cleanupVerified=True, evidence=self.evidence)
        self.doc['browser'] = dict(browserVersion='test', checks={c:True for c in q.BROWSER_CHECKS}, evidence=self.evidence)
        self.doc['benchmarks'] = [dict(case=c,passed=True,evidence=self.evidence) for c in ('10MiB','100MiB','512MiB','513MiB-limit','1000000-records','1000001-records-limit')]
        self.doc['pilot'] = [dict(engineer=str(i), firstReplaySeconds=100, tasks={t:dict(passed=True,uncoached=True) for t in q.TASKS}, evidence=self.evidence) for i in range(5)]

    def validate(self, doc=None, artifacts=None):
        return q.validate(doc or self.doc, self.base, '0.9.0', artifacts, digest='test')

    def test_complete_fixture(self):
        self.assertEqual([], self.validate())

    def test_pending_template(self):
        self.assertGreater(len(self.validate(q.template())),25)

    def test_stale_source_and_version(self):
        self.doc.update(sourceDigest='different',version='0.8.0')
        self.assertEqual(2,len(self.validate()))

    def test_cleanup_cancel_and_soak(self):
        p=self.doc['platforms']['windows-amd64']
        p['scenarios']['cancellation'][0]['cancelSeconds']=2.1
        p['scenarios']['wire'][0]['cleanupVerified']=False
        p['soak']['seconds']=7199
        self.assertEqual(3,len(self.validate()))

    def test_evidence_integrity(self):
        self.evidence[0]['sha256']='bad'
        self.assertTrue(any('checksum' in e for e in self.validate()))
        self.evidence[0]['path']='../outside.txt'
        self.assertTrue(any('escapes' in e for e in self.validate()))

    def test_pilot_thresholds(self):
        for p in self.doc['pilot'][:3]:
            p['tasks']['inspect-select']['passed']=False
            p['firstReplaySeconds']=601
        self.doc['pilot'][1]['engineer']='0'
        self.assertEqual(3,len(self.validate()))

    def test_nonfinite_metrics(self):
        self.doc['pilot'][0]['firstReplaySeconds']=float('nan')
        self.doc['platforms']['linux-amd64']['soak']['seconds']=float('inf')
        self.assertTrue(self.validate())

    def test_packaged_binary_binding(self):
        self.assertEqual(2,len(self.validate(artifacts=self.base)))
        for platform,p in self.doc['platforms'].items():
            suffix='.exe' if platform.startswith('windows') else ''
            f=self.base/('livewire-0.9.0-'+platform+suffix)
            f.write_bytes(b'fixture binary')
            p['binarySha256']=q.sha(f)
        self.assertEqual([],self.validate(artifacts=self.base))

    def test_recorder_exit_and_overwrite_protection(self):
        args=argparse.Namespace(output=self.base/'record',timeout=5,expected_exit=3,argv=[sys.executable,'-c','raise SystemExit(3)'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0,q.record(args))
        record=json.loads((args.output/'record.json').read_text())
        self.assertFalse(record['behaviorVerified'])
        self.assertFalse(record['cleanupVerified'])
        self.assertRaises(FileExistsError,q.record,args)

    def test_recorder_timeout_cannot_pass(self):
        args=argparse.Namespace(output=self.base/'timeout',timeout=0.05,expected_exit=0,argv=[sys.executable,'-c','import time; time.sleep(5)'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(1,q.record(args))
        record=json.loads((args.output/'record.json').read_text())
        self.assertTrue(record['timedOut'])
        self.assertFalse(record['exitMatched'])

    def test_short_soak_cannot_claim_qualification(self):
        args=argparse.Namespace(output=self.base/'soak',seconds=0.1,gap=0.01,timeout=5,expected_exit=0,argv=[sys.executable,'-c','pass'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0,q.soak(args))
        record=json.loads((args.output/'soak.json').read_text())
        self.assertFalse(record['passed'])
        self.assertFalse(record['qualificationDurationMet'])
        self.assertFalse(record['cleanupVerified'])

if __name__=='__main__':
    unittest.main()
