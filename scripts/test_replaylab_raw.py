"""Artifact integrity checks; these do not require packet privileges."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from replaylab_raw import Lab, collect_evidence, evidence_ref


class EvidenceTests(unittest.TestCase):
    def test_all_artifacts_are_bound_without_recursive_run_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            names = ["events.jsonl", "peer.jsonl", "peer-process.log", "udp.pcap",
                     "live-udp-00001.independent.pcap", "live-udp-00001.actual.pcap",
                     "live-udp-00001.report.json", "live-udp-00001.cli.log",
                     "live-udp-00001.tcpdump.log", "live-udp-00001.firewall.txt"]
            for name in names + ["live.run.json", "reproduce.run.json"]:
                (folder / name).write_text("synthetic evidence", encoding="utf-8")
            refs = collect_evidence(folder, {})
            self.assertEqual({r["path"] for r in refs}, set(names))
            self.assertTrue(all(len(r["sha256"]) == 64 for r in refs))

    def test_deleted_or_changed_checked_artifact_invalidates_evidence(self):
        for mutation in ("delete", "change"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                capture = folder / "capture.pcap"
                capture.write_bytes(b"independently checked traffic")
                ref = evidence_ref(folder, capture)
                if mutation == "delete":
                    capture.unlink()
                else:
                    capture.write_bytes(b"replacement traffic")
                with self.assertRaisesRegex(ValueError, "missing or changed"):
                    collect_evidence(folder, {ref["path"]: ref["sha256"]})

    def test_integrity_failure_preserves_an_interrupted_run(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            capture = folder / "capture.pcap"
            capture.write_bytes(b"checked traffic")
            ref = evidence_ref(folder, capture)
            lab = Lab.__new__(Lab)
            lab.out, lab.transcript = folder, folder / "events.jsonl"
            lab.args = SimpleNamespace(version="1.0.0", source_digest="synthetic")
            lab.results = {"live": {}}
            lab.started, lab.binary_sha = "2026-01-01T00:00:00Z", "synthetic"
            lab.checked_evidence = {ref["path"]: ref["sha256"]}
            capture.unlink()
            with self.assertRaisesRegex(ValueError, "missing or changed"):
                lab.finish(False, True)
            report = json.loads((folder / "live.run.json").read_text())
            self.assertTrue(report["interrupted"])
            self.assertIn(ref, report["evidence"])
            self.assertIn("evidence-error", lab.transcript.read_text())


if __name__ == "__main__":
    unittest.main()
