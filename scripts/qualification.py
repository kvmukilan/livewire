"""Record operator-run checks and enforce stable-release qualification.

No default command sends traffic. `record` executes only the supplied argv;
use it on an explicitly selected lab host/target. Evidence stays local unless
the maintainer deliberately includes a reviewed, redacted copy in a release.
"""
import argparse
import hashlib
import json
import math
import os
import platform
import re
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("capture", "application", "stateful-tcp", "udp", "icmp", "wire",
             "two-interface-dut", "cancellation", "driver-error", "interface-removal",
             "target-disconnect", "invalid-credentials", "disk-full", "report-collision")
BROWSER_CHECKS = ("preview", "changed-inputs", "start-stop", "results", "downloads",
                  "keyboard", "narrow-width", "desktop-width")
TASKS = ("inspect-select", "preview-replay", "compare-results", "repeat-stop", "bundle")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_digest():
    # Bind evidence to executable source and qualification tooling. Scanning
    # actual files also detects new, not-yet-tracked source during local work.
    paths = [p for folder in ("cmd", "internal", "scripts")
             for p in (ROOT / folder).rglob("*")
             if p.is_file() and p.suffix in (".go", ".html", ".py", ".cjs", ".ps1")]
    paths += [ROOT / "go.mod", ROOT / "go.sum", ROOT / "qualification/corpus.json"]
    h = hashlib.sha256()
    for p in sorted(paths, key=lambda p: p.relative_to(ROOT).as_posix()):
        h.update(p.relative_to(ROOT).as_posix().encode() + b"\0")
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))
        h.update(b"\0")
    return h.hexdigest()


def template():
    return {
        "schemaVersion": 1, "version": "0.9.0", "sourceDigest": source_digest(),
        "blockingFindings": ["Qualification has not been completed"],
        "platforms": {platform: {"os": "", "driver": "", "nic": "", "dut": "",
            "firmware": "", "binarySha256": "", "scenarios": {s: [] for s in SCENARIOS},
            "soak": {"seconds": 0, "passed": False, "cleanupVerified": False, "evidence": []}}
            for platform in ("windows-amd64", "linux-amd64")},
        "browser": {"browserVersion": "", "checks": {s: False for s in BROWSER_CHECKS}, "evidence": []},
        "benchmarks": [], "pilot": [],
    }


def finite_number(x):
    return type(x) in (int, float) and math.isfinite(x)


def validate(doc, base, version, artifacts=None, digest=None):
    errors = []

    def need(condition, message):
        if not condition:
            errors.append(message)

    def evidence(items, label):
        need(isinstance(items, list) and len(items) > 0, label + ": missing evidence")
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                errors.append(label + ": invalid evidence entry")
                continue
            path = (base / item.get("path", "")).resolve()
            need(path.is_relative_to(base.resolve()), label + ": evidence escapes its directory")
            if not path.is_relative_to(base.resolve()):
                continue
            need(path.is_file(), label + ": evidence file missing")
            if path.is_file():
                need(sha(path) == item.get("sha256"), label + ": evidence checksum mismatch")

    need(doc.get("schemaVersion") == 1, "unsupported qualification schema")
    need(doc.get("version") == version, "qualification version mismatch")
    need(doc.get("sourceDigest") == (digest or source_digest()), "qualification source changed; requalify")
    need(doc.get("blockingFindings") == [], "unresolved blocking findings")
    for platform in ("windows-amd64", "linux-amd64"):
        p = doc.get("platforms", {}).get(platform, {})
        for field in ("os", "driver", "nic", "dut", "firmware", "binarySha256"):
            need(isinstance(p.get(field), str) and bool(p[field].strip()), platform + ": missing " + field)
        if artifacts:
            suffix = ".exe" if platform.startswith("windows") else ""
            binary = artifacts / ("livewire-" + version + "-" + platform + suffix)
            need(binary.is_file(), platform + ": packaged binary missing")
            if binary.is_file():
                need(sha(binary) == p.get("binarySha256"), platform + ": tested binary differs from release")
        for scenario in SCENARIOS:
            runs = p.get("scenarios", {}).get(scenario, [])
            need(len(runs) >= 3, platform + "/" + scenario + ": three consecutive passes required")
            for r in runs[-3:]:
                label = platform + "/" + scenario
                need(r.get("passed") is True and r.get("cleanupVerified") is True, label + ": failed result/cleanup")
                need(bool(r.get("expectedResult")) and bool(r.get("observedResult")), label + ": missing expected/observed behavior")
                if scenario == "cancellation":
                    seconds = r.get("cancelSeconds")
                    need(finite_number(seconds) and 0 <= seconds <= 2, label + ": cancellation exceeds two seconds or is unmeasured")
                evidence(r.get("evidence"), label)
        soak = p.get("soak", {})
        seconds = soak.get("seconds")
        need(finite_number(seconds) and seconds >= 7200, platform + ": two-hour soak missing")
        need(soak.get("passed") is True and soak.get("cleanupVerified") is True, platform + ": soak failed or cleanup unverified")
        evidence(soak.get("evidence"), platform + "/soak")
    browser = doc.get("browser", {})
    need(bool(browser.get("browserVersion")), "browser version missing")
    for check in BROWSER_CHECKS:
        need(browser.get("checks", {}).get(check) is True, "browser check missing: " + check)
    evidence(browser.get("evidence"), "browser")
    cases = {b.get("case"): b for b in doc.get("benchmarks", [])}
    for case in ("10MiB", "100MiB", "512MiB", "513MiB-limit", "1000000-records", "1000001-records-limit"):
        b = cases.get(case, {})
        need(b.get("passed") is True, "benchmark missing/failed: " + case)
        evidence(b.get("evidence"), "benchmark/" + case)
    pilot = doc.get("pilot", [])
    need(len(pilot) == 5, "five pilot engineers required")
    ids = [p.get("engineer") for p in pilot]
    need(all(isinstance(x, str) and x.strip() for x in ids) and len(set(ids)) == 5, "pilot engineer identifiers must be distinct")
    successes, times = 0, []
    for p in pilot:
        tasks = p.get("tasks", {})
        for task in TASKS:
            r = tasks.get(task, {})
            need(r.get("uncoached") is True, "pilot task must be uncoached: " + task)
            successes += r.get("passed") is True
        seconds = p.get("firstReplaySeconds")
        need(finite_number(seconds) and seconds >= 0, "invalid pilot first-replay time")
        if finite_number(seconds) and seconds >= 0:
            times.append(seconds)
        evidence(p.get("evidence"), "pilot")
    need(successes >= 23, "pilot completion below 23/25")
    need(len(times) == 5 and statistics.median(times) <= 600, "pilot median first replay exceeds ten minutes or is unmeasured")
    return errors


def record(args):
    if not finite_number(args.timeout) or args.timeout <= 0:
        raise ValueError("timeout must be positive and finite")
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv:
        raise ValueError("record requires an explicit command after --")
    # Do not put credentials in argv: transcripts are private and still need
    # review/redaction before sharing. No shell interpolation is performed.
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    start = time.monotonic()
    with (args.output / "stdout.txt").open("xb") as out, (args.output / "stderr.txt").open("xb") as err:
        try:
            proc = subprocess.run(argv, stdout=out, stderr=err, timeout=args.timeout, check=False)
            code, timed_out = proc.returncode, False
        except subprocess.TimeoutExpired:
            code, timed_out = None, True
    data = {"argv": argv, "elapsedSeconds": time.monotonic()-start, "exitCode": code,
            "timedOut": timed_out, "sourceDigest": source_digest(), "expectedExit": args.expected_exit,
            "exitMatched": code == args.expected_exit and not timed_out,
            "behaviorVerified": False, "cleanupVerified": False,
            "files": [{"path": n, "sha256": sha(args.output / n)} for n in ("stdout.txt", "stderr.txt")]}
    (args.output / "record.json").write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(data, indent=2))
    return 0 if data["exitMatched"] else 1


def peak_rss(pid):
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ("peak", "working", "peakPaged", "paged", "peakNonPaged", "nonPaged", "pagefile", "peakPagefile")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        handle = kernel.OpenProcess(0x410, False, pid)
        if not handle:
            return 0
        try:
            counters = Counters(); counters.cb = ctypes.sizeof(counters)
            return counters.peak if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb) else 0
        finally:
            kernel.CloseHandle(handle)
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return 0


def benchmark(args):
    args.output.mkdir(parents=True, exist_ok=False)
    binary = args.output.resolve() / ("qualifybench.exe" if sys.platform == "win32" else "qualifybench")
    subprocess.run(["go", "build", "-o", str(binary), "scripts/qualifybench.go"], cwd=ROOT, check=True)
    results = []
    for name, argv in (("10MiB", ["-mib", "10"]), ("100MiB", ["-mib", "100"]),
                       ("512MiB", ["-mib", "512"]), ("513MiB-limit", ["-mib", "513"]),
                       ("1000000-records", ["-records", "1000000"]), ("1000001-records-limit", ["-records", "1000001"])):
        stdout, stderr = args.output / (name + ".json"), args.output / (name + ".stderr.txt")
        peak, start = 0, time.monotonic()
        with stdout.open("xb") as out, stderr.open("xb") as err:
            proc = subprocess.Popen([str(binary)] + argv, stdout=out, stderr=err)
            while proc.poll() is None:
                peak = max(peak, peak_rss(proc.pid))
                if time.monotonic()-start > 300:
                    proc.kill(); proc.wait()
                    break
                time.sleep(0.01)
        result = json.loads(stdout.read_text()) if stdout.stat().st_size else {}
        result.update(case=name, observedPeakRSSBytes=peak,
                      hostOS=platform.platform(), processor=platform.processor(), logicalCPUs=os.cpu_count(),
                      rssMethod="Observed OS process high-water mark at 10ms intervals; excludes fixture file cache",
                      passed=proc.returncode == 0 and result.get("passed") is True,
                      sourceDigest=source_digest())
        metrics = args.output / (name + ".metrics.json")
        metrics.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
        results.append({"case": name, "passed": result["passed"], "evidence": [{"path": metrics.name, "sha256": sha(metrics)}]})
        print(json.dumps(result), flush=True)
    (args.output / "benchmarks.json").write_text(json.dumps(results, indent=2)+"\n", encoding="utf-8")
    return 0 if all(r["passed"] for r in results) else 1


def corpus(args):
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((ROOT / "qualification/corpus.json").read_text())
    grouped = {}
    for case in manifest["cases"]:
        grouped.setdefault(case["package"], []).append(case["test"])
    results = []
    for package, tests in grouped.items():
        pattern = "^(" + "|".join(re.escape(t) for t in tests) + ")$"
        proc = subprocess.run(["go", "test", "-json", "-count=1", "-run", pattern, package],
                              cwd=ROOT, capture_output=True, text=True, timeout=300)
        log = args.output / (package.replace("./", "").replace("/", "-") + ".jsonl")
        log.write_text(proc.stdout, encoding="utf-8")
        log.with_suffix(".stderr.txt").write_text(proc.stderr, encoding="utf-8")
        passed = set()
        for line in proc.stdout.splitlines():
            event = json.loads(line)
            if event.get("Action") == "pass":
                passed.add(event.get("Test"))
        ok = proc.returncode == 0 and all(t in passed for t in tests)
        results.append(dict(package=package, tests=tests, passed=ok, evidence={"path": log.name, "sha256": sha(log)}))
        print(package + (": passed" if ok else ": FAILED (missing, skipped, or failing test)"), flush=True)
    (args.output / "corpus-results.json").write_text(json.dumps(results, indent=2)+"\n", encoding="utf-8")
    return 0 if all(r["passed"] for r in results) else 1


def soak(args):
    if not finite_number(args.seconds) or args.seconds <= 0 or not finite_number(args.gap) or args.gap < 0:
        raise ValueError("seconds must be positive and gap nonnegative, both finite")
    if not finite_number(args.timeout) or args.timeout <= 0:
        raise ValueError("timeout must be positive and finite")
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv:
        raise ValueError("soak requires an explicit lab command after --")
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    start, attempt, success = time.monotonic(), 0, True
    interrupted = False
    try:
        while time.monotonic() - start < args.seconds:
            attempt += 1
            call = argparse.Namespace(output=args.output / ("attempt-" + str(attempt)),
                timeout=args.timeout, expected_exit=args.expected_exit,
                argv=[v.replace("{attempt}", str(attempt)) for v in argv])
            if record(call) != 0:
                success = False
                break
            time.sleep(min(args.gap, max(0, args.seconds - (time.monotonic()-start))))
    except KeyboardInterrupt:
        interrupted, success = True, False
    elapsed = time.monotonic() - start
    result = dict(seconds=elapsed, requestedSeconds=args.seconds, attempts=attempt,
        commandsPassed=success and not interrupted, interrupted=interrupted,
        passed=False, cleanupVerified=False, qualificationDurationMet=elapsed >= 7200,
        sourceDigest=source_digest(), hostOS=platform.platform(),
        nextAction="Review attempt behavior, memory/handle observations, and host cleanup before marking qualification passed.")
    (args.output / "soak.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init"); init.add_argument("output", type=Path)
    check = sub.add_parser("validate")
    check.add_argument("manifest", type=Path); check.add_argument("--version", required=True)
    check.add_argument("--artifacts", type=Path)
    bench = sub.add_parser("benchmark"); bench.add_argument("--output", type=Path, required=True)
    corp = sub.add_parser("corpus"); corp.add_argument("--output", type=Path, required=True)
    rec = sub.add_parser("record")
    rec.add_argument("--output", required=True, type=Path); rec.add_argument("--timeout", type=float, default=300)
    rec.add_argument("--expected-exit", type=int, default=0); rec.add_argument("argv", nargs=argparse.REMAINDER)
    soak_cmd = sub.add_parser("soak")
    soak_cmd.add_argument("--output", required=True, type=Path)
    soak_cmd.add_argument("--seconds", type=float, default=7200)
    soak_cmd.add_argument("--gap", type=float, default=1)
    soak_cmd.add_argument("--timeout", type=float, default=300)
    soak_cmd.add_argument("--expected-exit", type=int, default=0)
    soak_cmd.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "init":
        with args.output.open("x", encoding="utf-8") as f:
            json.dump(template(), f, indent=2); f.write("\n")
        return 0
    if args.action == "record":
        return record(args)
    if args.action == "benchmark":
        return benchmark(args)
    if args.action == "corpus":
        return corpus(args)
    if args.action == "soak":
        return soak(args)
    doc = json.loads(args.manifest.read_text(encoding="utf-8"))
    errors = validate(doc, args.manifest.parent, args.version, args.artifacts)
    print(json.dumps({"ready": not errors, "blockers": errors}, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
        print("qualification: " + str(e), file=sys.stderr)
        sys.exit(1)
