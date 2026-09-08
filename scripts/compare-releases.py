"""Compare the published Windows builds using synthetic captures and localhost.

No packet interface is opened: live checks use HTTP's socket adapter, while
mixed captures are inspected offline. Requires Python 3 and a current EXE.
"""
import argparse
import gzip
import hashlib
import json
import random
import socketserver
import struct
import subprocess
import threading
from pathlib import Path


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(reverse, port, seq, ack, flags, payload=b""):
    src, dst = bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20])
    sport, dport = 41000, port
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    eth = bytes.fromhex("0200000000020200000000010800")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 0, 0, 64, 6, 0, src, dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    return eth + ip + tcp + payload


def capture(path, port, body, background=False):
    request = b"GET /download HTTP/1.1\r\nHost: device.local\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    frames = [frame(False, port, 100, 0, 2), frame(True, port, 900, 101, 18),
              frame(False, port, 101, 901, 16), frame(False, port, 101, 901, 24, request),
              frame(True, port, 901, 101 + len(request), 24, response)]
    if background:
        frames.append(bytes.fromhex("ffffffffffff02000000000108060001080006040001020000000001c000020a000000000000c0000214"))
    with path.open("xb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, data in enumerate(frames):
            output.write(struct.pack("<IIII", 1700000000, 1000 * i, len(data), len(data)))
            output.write(data)
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    body = gzip.compress(random.Random(42).randbytes(4096), mtime=0)
    results = {}
    for label, executable in [("0.7", repo / "dist/v0.7.0/livewire-0.7.0-windows-amd64.exe"),
                              ("0.8", repo / "dist/v0.8.0/livewire-0.8.0-windows-amd64.exe"),
                              ("0.9", repo / "livewire.exe")]:
        state = {"requests": 0}

        class HTTP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                received = b""
                while b"\r\n\r\n" not in received and len(received) < 65536:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    received += chunk
                state["requests"] += 1
                self.request.sendall(state["response"])

        with socketserver.ThreadingTCPServer(("127.0.0.1", 0), HTTP) as server:
            server.daemon_threads = True
            port = server.server_address[1]
            plain = output / (label + "-gzip.pcap")
            mixed = output / (label + "-gzip-arp.pcap")
            state["response"] = capture(plain, port, body)
            capture(mixed, port, body, True)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            commands = {
                "help": [],
                "gzip-inspection": ["check", str(plain), "-details"],
                "mixed-inspection": ["check", str(mixed), "-details"],
                "gzip-replay": ["reproduce", str(plain), "-t", "127.0.0.1", "-report", str(output / (label + "-replay.json"))],
            }
            if label != "0.9":
                commands["gzip-replay"] += ["-i", "comparison-no-packet-interface"]
            else:
                commands["gzip-replay"] += ["--mode", "application"]
                commands["selected-preview"] = ["reproduce", str(mixed), "--mode", "application", "--session", "tcp-0", "--dry-run"]
                commands["selected-replay"] = ["reproduce", str(mixed), "--mode", "application", "--session", "tcp-0", "-t", "127.0.0.1", "-report", str(output / "0.9-selected.json")]
            outcomes = {}
            try:
                for name, command in commands.items():
                    run = subprocess.run([str(executable), *command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
                    (output / (label + "-" + name + ".txt")).write_bytes(run.stdout)
                    outcomes[name] = {"exitCode": run.returncode, "outputSHA256": hashlib.sha256(run.stdout).hexdigest()}
            finally:
                server.shutdown()
                worker.join(3)
            outcomes["localhostRequests"] = state["requests"]
            results[label] = outcomes
    (output / "comparison.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    assert results["0.7"]["gzip-replay"]["exitCode"] == 0
    assert results["0.7"]["localhostRequests"] == 1
    assert results["0.8"]["gzip-replay"]["exitCode"] != 0
    assert results["0.8"]["localhostRequests"] == 0
    assert results["0.9"]["gzip-replay"]["exitCode"] == 0
    assert results["0.9"]["selected-preview"]["exitCode"] == 0
    assert results["0.9"]["selected-replay"]["exitCode"] == 0
    assert results["0.9"]["localhostRequests"] == 2


if __name__ == "__main__":
    main()
