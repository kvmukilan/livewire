"""Artifact integrity checks; these do not require packet privileges."""
import json
import contextlib
import io
import struct
import signal
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from replaylab_raw import Lab, collect_evidence, corrected_contract, decode_pcap, evidence_ref, ethernet_frames, is_stateless, main, sha, stateless_fixture, verify_stateless_report, verify_wire_capture, verify_wire_report, wire_fixture


class EvidenceTests(unittest.TestCase):
    def test_all_artifacts_are_bound_without_recursive_run_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            names = ["events.jsonl", "peer.jsonl", "peer-process.log", "udp.pcap",
                     "live-udp-00001.independent.pcap", "live-udp-00001.actual.pcap",
                     "live-udp-00001.report.json", "live-udp-00001.cli.log",
                     "live-udp-00001.tcpdump.log", "live-udp-00001.firewall.txt"]
            for name in names + ["live.run.json", "reproduce.run.json", "replay.run.json"]:
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


class StatelessTests(unittest.TestCase):
    def test_versioned_command_routing_before_any_network_setup(self):
        class Parsed(Exception):
            pass
        def parsed(version, commands):
            found = []
            def construct(args):
                found.append(args)
                raise Parsed()
            argv = ["replaylab_raw.py", "--binary", "synthetic", "--output", "synthetic", "--source-digest", "synthetic", "--version", version]
            for command in commands:
                argv += ["--command", command]
            with patch("sys.argv", argv), patch("replaylab_raw.os.geteuid", return_value=0, create=True), patch("replaylab_raw.Lab", side_effect=construct):
                with self.assertRaises(Parsed):
                    main()
            return found[0]
        self.assertEqual(parsed("1.0.1", []).command, ["live", "reproduce"])
        self.assertEqual(parsed("1.1.0", []).command, ["live"])
        self.assertNotEqual(parsed("1.0.1", ["reproduce"]).case, ["mixed-frames"])
        for command in ("reproduce", "replay"):
            args = parsed("1.1.0", [command])
            self.assertEqual((args.command, args.case), ([command], ["mixed-frames"]))
            self.assertTrue(is_stateless(command, args.version))
        self.assertFalse(is_stateless("reproduce", "1.0.1"))
        self.assertTrue(corrected_contract("v1.1.0-rc.1"))
        for tail in (["--command", "live", "--command", "reproduce"], ["--command", "reproduce", "--command", "replay"], ["--command", "live", "--command", "live"], ["--command", "reproduce", "--netem"], ["--command", "live", "--case", "mixed-frames"]):
            argv = ["replaylab_raw.py", "--binary", "synthetic", "--output", "synthetic", "--source-digest", "synthetic", "--version", "1.1.0", *tail]
            with self.subTest(tail=tail), patch("sys.argv", argv), patch("replaylab_raw.Lab") as constructor, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main()
                constructor.assert_not_called()

    def test_corrected_stateless_fixture_covers_protocol_bytes_and_actual_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture, actual = Path(directory) / "mixed.pcap", Path(directory) / "actual.pcap"
            frames = stateless_fixture(fixture, "1.1.0")
            self.assertEqual(len(frames), 22)
            rows = decode_pcap(fixture)
            ports = {row.get("dport") for row in rows} | {row.get("sport") for row in rows}
            self.assertTrue({20, 21, 22, 53, 80, 443, 502, 990, 1883, 1884, 20000}.issubset(ports))
            payloads = [row.get("payload", b"") for row in rows]
            self.assertTrue(any(b"MQTT\x04" in payload for payload in payloads))
            self.assertTrue(any(b"MQTT\x05" in payload for payload in payloads))
            self.assertIn(b"AUTH TLS\r\n", payloads)
            self.assertTrue(any(payload.startswith(b"SSH-2.0-") for payload in payloads))
            self.assertTrue(any(payload.startswith(b"\x05\x64") for payload in payloads))
            data = fixture.read_bytes()[:24]
            for frame in frames * 3:
                data += struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame
            actual.write_bytes(data)
            for command in ("reproduce", "replay"):
                report = {"tool": "livewire", "version": "1.1.0", "command": command, "mode": "wire", "status": "wire", "completed": True, "verified": False, "passes": 3, "framesPerPass": 22, "framesSent": 66, "captureDigest": "sha256:" + sha(fixture)}
                self.assertEqual(verify_stateless_report(report, fixture, actual, 3, "1.1.0", command), 66)
                for wrong in ("live", "replay" if command == "reproduce" else "reproduce", None):
                    with self.subTest(command=command, wrong=wrong), self.assertRaises(ValueError):
                        verify_stateless_report(dict(report, command=wrong), fixture, actual, 3, "1.1.0", command)

    def test_wire_interleaved_sessions_reject_session_grouping_and_tie_reordering(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture, capture = Path(directory) / "wire.pcap", Path(directory) / "observed.pcap"
            frames = wire_fixture(fixture)
            self.assertEqual(len(frames), 80)
            rows = decode_pcap(fixture)
            self.assertEqual(len({(p["proto"], p["sport"], p["dport"]) for p in rows}), 40)
            self.assertEqual({p["proto"] for p in rows}, {6, 17})
            report = {"version": "1.0.1", "attempts": 3, "selectedPackets": 80, "captureDigest": "sha256:" + sha(fixture), "outcome": {"status": "wire"}, "sessions": [{"attempt": attempt, "sessionId": "flow-%d" % session, "completed": True, "verified": False, "matched": False, "status": "wire", "mode": "wire", "sent": 2, "packetCount": 2} for attempt in range(1, 4) for session in range(40)]}
            verify_wire_report(report, fixture, 3, "1.0.1")
            for key, value in (("completed", False), ("verified", True), ("matched", True), ("sent", 1), ("attempt", 1)):
                changed = json.loads(json.dumps(report))
                changed["sessions"][-1][key] = value
                with self.subTest(report=key), self.assertRaises(ValueError):
                    verify_wire_report(changed, fixture, 3, "1.0.1")
            def observed(items):
                data = fixture.read_bytes()[:24]
                for frame in items:
                    data += struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame
                capture.write_bytes(data)
            observed(frames * 3)
            self.assertEqual(verify_wire_capture(fixture, capture, 3), 240)
            grouped = [frame for pair in zip(frames[:40], frames[40:]) for frame in pair]
            for items in (grouped * 3, [frames[1], frames[0]] + frames[2:] + frames * 2, frames * 3 + frames[:1], (frames * 3)[:-1]):
                observed(items)
                with self.assertRaisesRegex(ValueError, "bytes/order/count"):
                    verify_wire_capture(fixture, capture, 3)

    def test_sigterm_runs_cleanup_and_records_interruption(self):
        lab = Mock()
        lab.cleanup.return_value = True
        lab.setup.side_effect = lambda: signal.raise_signal(signal.SIGTERM)
        previous = signal.getsignal(signal.SIGTERM)
        with patch("sys.argv", ["replaylab_raw.py", "--binary", "synthetic", "--output", "synthetic", "--source-digest", "synthetic", "--version", "1.0.1", "--command", "replay"]), patch("replaylab_raw.os.geteuid", return_value=0, create=True), patch("replaylab_raw.Lab", return_value=lab):
            with self.assertRaises(KeyboardInterrupt): main()
        lab.cleanup.assert_called_once_with()
        lab.finish.assert_called_once_with(True, True)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_exact_mixed_frames_and_unverified_report_required(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            fixture, capture = folder / "mixed.pcap", folder / "observed.pcap"
            expected = stateless_fixture(fixture)
            self.assertEqual(ethernet_frames(fixture), expected)
            self.assertEqual(len(expected), 7)
            def write_frames(frames):
                data = fixture.read_bytes()[:24]
                for frame in frames:
                    data += struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame
                capture.write_bytes(data)
            report = {"tool": "livewire", "version": "1.0.1", "mode": "wire", "status": "wire", "completed": True, "verified": False, "passes": 3, "framesPerPass": 7, "framesSent": 21, "captureDigest": "sha256:" + sha(fixture)}
            write_frames(expected * 3)
            self.assertEqual(verify_stateless_report(report, fixture, capture, 3, "1.0.1"), 21)
            for mutation in ("missing", "extra", "order", "bytes"):
                with self.subTest(mutation=mutation):
                    frames = expected * 3
                    if mutation == "missing": frames.pop()
                    elif mutation == "extra": frames.append(expected[0])
                    elif mutation == "order": frames[0], frames[1] = frames[1], frames[0]
                    else: frames[0] = frames[0][:-1] + bytes([frames[0][-1] ^ 1])
                    write_frames(frames)
                    with self.assertRaisesRegex(ValueError, "bytes/order/count"):
                        verify_stateless_report(report, fixture, capture, 3, "1.0.1")
            write_frames(expected * 3)
            for key, value in (("verified", True), ("completed", False), ("framesSent", 20), ("passes", 2), ("status", "matched"), ("captureDigest", "sha256:wrong"), ("version", "1.0.0")):
                with self.subTest(field=key), self.assertRaisesRegex(ValueError, "report differs"):
                    verify_stateless_report(dict(report, **{key: value}), fixture, capture, 3, "1.0.1")

    def test_truncated_or_non_ethernet_observation_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "mixed.pcap"
            stateless_fixture(fixture)
            original = fixture.read_bytes()
            for data in (original[:20], original[:-1], original + b"x", original[:20] + struct.pack("<I", 101) + original[24:]):
                fixture.write_bytes(data)
                with self.assertRaises(ValueError): ethernet_frames(fixture)


if __name__ == "__main__":
    unittest.main()
