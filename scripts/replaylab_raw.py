#!/usr/bin/env python3
"""Owned Linux namespace lab for the actual livewire packet CLI.

Only randomly named namespaces/interfaces created by this process are removed.
The lab is software evidence: it does not qualify physical NICs or field devices.
"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import math
import os
import re
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

C4, S4 = "198.18.42.1", "198.18.42.2"
C6, S6 = "fd42:9876::1", "fd42:9876::2"
CASES = ["dns-udp", "udp", "icmp4", "icmp6", "stateful-tcp", "transport-tcp", "wire"]
TCP_REQ, TCP_RESP = b"STATEFUL REQUEST\n", b"STATEFUL RESPONSE\n"
UDP_REQ, UDP_RESP = b"udp-lab-request", b"udp-lab-response"
WIRE_REQ = b"wire-lab-request"
ECHO = b"packet-lab-echo"
STATELESS_MACS = (bytes.fromhex("024242000001"), bytes.fromhex("024242000002"))
DNS_QUERY = bytes.fromhex("123401000001000000000000") + b"\x03lab\x07example\x00\x00\x01\x00\x01"


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


class LabContinuity:
    """v1.1+ wall-clock limits mirrored by qualification.LabContinuity.

    Leave margin above 25s subprocess deadlines and 20s round gaps, but never
    credit host suspension as sustained activity. Historical gates are unchanged.
    """
    MAX_EXECUTION, MAX_IDLE, MAX_CASE_GAP = 120, 60, 300

    def __init__(self, version):
        self.enabled = corrected_contract(version)
        self.last_finished, self.case_finished = None, {}

    @staticmethod
    def timestamp(value):
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))

    def check_start(self, name, started):
        if not self.enabled:
            return
        started = self.timestamp(started)
        if self.last_finished is not None:
            gap = (started - self.last_finished).total_seconds()
            if not 0 <= gap <= self.MAX_IDLE:
                raise ValueError("lab continuity: %s idle gap %ss outside 0..%s" % (name, gap, self.MAX_IDLE))
        if name in self.case_finished:
            gap = (started - self.case_finished[name]).total_seconds()
            if gap > self.MAX_CASE_GAP:
                raise ValueError("lab continuity: %s case gap %ss exceeds %s" % (name, gap, self.MAX_CASE_GAP))

    def observe(self, name, started, finished):
        if not self.enabled:
            return
        self.check_start(name, started)
        started, finished = self.timestamp(started), self.timestamp(finished)
        duration = (finished - started).total_seconds()
        if not 0 <= duration <= self.MAX_EXECUTION:
            raise ValueError("lab continuity: %s execution duration %ss outside 0..%s" % (name, duration, self.MAX_EXECUTION))
        self.last_finished = self.case_finished[name] = finished


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def evidence_ref(folder, path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 << 20:
        raise ValueError("evidence is missing, nonregular or exceeds 64MiB: " + str(path))
    name = path.resolve().relative_to(folder.resolve()).as_posix()
    return {"path": name, "sha256": sha(path)}


def collect_evidence(folder, expected):
    """Bind every owned artifact and reject loss/change after a successful check."""
    found = {}
    for path in sorted(folder.iterdir()):
        if path.name in ("live.run.json", "reproduce.run.json", "replay.run.json"):
            continue
        ref = evidence_ref(folder, path)
        found[ref["path"]] = ref["sha256"]
    for name, digest in expected.items():
        if found.get(name) != digest:
            raise ValueError("checked evidence is missing or changed: " + name)
    return [{"path": name, "sha256": digest} for name, digest in sorted(found.items())]


def checksum(b):
    if len(b) & 1:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 65535) + (s >> 16)
    return (~s) & 65535


def dns_reply(query):
    if query[2:] != DNS_QUERY[2:]:
        raise ValueError("unexpected DNS request")
    return query[:2] + bytes.fromhex("81800001000100000000") + query[12:] + bytes.fromhex("c00c000100010000003c0004c000027b")


def packet(src, dst, proto, body, cmac, smac, reverse=False):
    a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    eth = (cmac + smac if reverse else smac + cmac)
    if a.version == 4:
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 1, 0x4000, 64, proto, 0, a.packed, b.packed)
        hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
        return eth + b"\x08\x00" + hdr + body
    return eth + b"\x86\xdd" + struct.pack("!IHBB16s16s", 6 << 28, len(body), proto, 64, a.packed, b.packed) + body


def transport(src, dst, proto, body, checksum_offset):
    a, b = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if a.version == 4:
        pseudo = a.packed + b.packed + struct.pack("!BBH", 0, proto, len(body))
    else:
        pseudo = a.packed + b.packed + struct.pack("!I3xB", len(body), proto)
    value = checksum(pseudo + body)
    return body[:checksum_offset] + struct.pack("!H", value or 65535) + body[checksum_offset + 2:]


def fixtures(folder, cmac, smac):
    def udp(port, req, resp=None):
        out = []
        for reverse, data in [(False, req)] + ([(True, resp)] if resp is not None else []):
            src, dst, sp, dp = (S4, C4, port, 40000) if reverse else (C4, S4, 40000, port)
            body = struct.pack("!HHHH", sp, dp, 8 + len(data), 0) + data
            out.append(packet(src, dst, 17, transport(src, dst, 17, body, 6), cmac, smac, reverse))
        return out

    def tcp():
        cn, sn, nr, ns = 1000, 9000, len(TCP_REQ), len(TCP_RESP)
        rows = [(False, cn, 0, 2, b""), (True, sn, cn + 1, 18, b""),
                (False, cn + 1, sn + 1, 16, b""), (False, cn + 1, sn + 1, 24, TCP_REQ),
                (True, sn + 1, cn + 1 + nr, 24, TCP_RESP),
                (False, cn + 1 + nr, sn + 1 + ns, 16, b""),
                (False, cn + 1 + nr, sn + 1 + ns, 17, b""),
                (True, sn + 1 + ns, cn + 2 + nr, 17, b""),
                (False, cn + 2 + nr, sn + 2 + ns, 16, b"")]
        out = []
        for rev, seq, ack, flags, data in rows:
            src, dst, sp, dp = (S4, C4, 19001, 40000) if rev else (C4, S4, 40000, 19001)
            body = struct.pack("!HHIIBBHHH", sp, dp, seq, ack, 80, flags, 65535, 0, 0) + data
            out.append(packet(src, dst, 6, transport(src, dst, 6, body, 16), cmac, smac, rev))
        return out

    def icmp(v6):
        out = []
        for reverse in (False, True):
            src, dst = ((S6, C6) if reverse else (C6, S6)) if v6 else ((S4, C4) if reverse else (C4, S4))
            typ = (129 if reverse else 128) if v6 else (0 if reverse else 8)
            body = struct.pack("!BBHHH", typ, 0, 0, 4242, 1) + ECHO
            if v6:
                body = transport(src, dst, 58, body, 2)
            else:
                body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
            out.append(packet(src, dst, 58 if v6 else 1, body, cmac, smac, reverse))
        return out

    rows = {"dns-udp": udp(53, DNS_QUERY, dns_reply(DNS_QUERY)), "udp": udp(19000, UDP_REQ, UDP_RESP),
            "icmp4": icmp(False), "icmp6": icmp(True), "stateful-tcp": tcp(), "transport-tcp": tcp()}
    for name, frames in rows.items():
        with open(folder / (name + ".pcap"), "wb") as f:
            f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for i, frame in enumerate(frames):
                f.write(struct.pack("<IIII", 1700000000, i * 20000, len(frame), len(frame)))
                f.write(frame)
    wire_fixture(folder / "wire.pcap")


def wire_fixture(path):
    """Forty sessions interleave two frames each, including timestamp ties."""
    cmac, smac = STATELESS_MACS
    frames = []
    for phase in range(2):
        for session in range(40):
            payload = WIRE_REQ + (":%02d:%d" % (session, phase)).encode("ascii")
            sp, dp = 41000 + session, 19100 + session
            if session % 2:
                body = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload
                proto, offset = 17, 6
            else:
                body = struct.pack("!HHIIBBHHH", sp, dp, 1000 + phase * len(payload), 9000, 80, 24, 65535, 0, 0) + payload
                proto, offset = 6, 16
            frames.append(packet(C4, S4, proto, transport(C4, S4, proto, body, offset), cmac, smac).ljust(60, b"\0"))
    with Path(path).open("xb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            output.write(struct.pack("<IIII", 1700000000, (i // 4) * 2000, len(frame), len(frame)) + frame)
    return frames


def serve(log_path):
    lock = threading.Lock()
    def record(case, request, response):
        with lock, open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"at": utc(), "case": case, "request": request.hex(), "response": response.hex()}) + "\n")
    def datagrams(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((S4, port))
        while True:
            request, addr = sock.recvfrom(65535)
            if name == "dns-udp":
                response = dns_reply(request)
            elif name == "udp":
                if request != UDP_REQ: raise ValueError("UDP payload differs")
                response = UDP_RESP
            else:
                if request != WIRE_REQ: raise ValueError("wire payload differs")
                response = b"wire-lab-response"
            sock.sendto(response, addr)
            record(name, request, response)
    def connection(conn):
        try:
            conn.settimeout(5)
            request = b""
            while not request.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk: break
                request += chunk
            if request != TCP_REQ: raise ValueError("TCP request differs: " + repr(request))
            # Exercise response segmentation independently of captured boundaries.
            conn.sendall(TCP_RESP[:5])
            time.sleep(0.003)
            conn.sendall(TCP_RESP[5:])
            record("tcp", request, TCP_RESP)
            while conn.recv(4096):
                pass
        except (ConnectionError, TimeoutError):
            pass
        finally:
            conn.close()
    def stream():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((S4, 19001))
        sock.listen(32)
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=connection, args=(conn,), daemon=True).start()
    for port, name in [(53, "dns-udp"), (19000, "udp"), (19003, "wire")]:
        threading.Thread(target=datagrams, args=(port, name), daemon=True).start()
    threading.Thread(target=stream, daemon=True).start()
    print("ready", flush=True)
    while True:
        time.sleep(1)


def decode_pcap(path):
    data = Path(path).read_bytes()
    if len(data) < 24: raise ValueError("independent capture missing")
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    out, off = [], 24
    while off + 16 <= len(data):
        _, _, length, _ = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        frame, off = data[off:off + length], off + length
        if len(frame) < 34: continue
        kind = struct.unpack_from("!H", frame, 12)[0]
        if kind == 0x800:
            ihl, proto = (frame[14] & 15) * 4, frame[23]
            src, dst = socket.inet_ntop(socket.AF_INET, frame[26:30]), socket.inet_ntop(socket.AF_INET, frame[30:34])
            l4 = frame[14 + ihl:14 + struct.unpack_from("!H", frame, 16)[0]]
        elif kind == 0x86DD and len(frame) >= 54:
            proto = frame[20]
            src, dst = socket.inet_ntop(socket.AF_INET6, frame[22:38]), socket.inet_ntop(socket.AF_INET6, frame[38:54])
            l4 = frame[54:54 + struct.unpack_from("!H", frame, 18)[0]]
        else: continue
        row = {"src": src, "dst": dst, "proto": proto}
        if proto in (6, 17) and len(l4) >= (20 if proto == 6 else 8):
            row["sport"], row["dport"] = struct.unpack_from("!HH", l4)
            header = (l4[12] >> 4) * 4 if proto == 6 else 8
            row["payload"] = l4[header:]
            if proto == 6:
                row["seq"], row["ack"] = struct.unpack_from("!II", l4, 4)
                row["flags"] = l4[13]
        elif proto in (1, 58) and len(l4) >= 8:
            row["type"], row["payload"] = l4[0], l4[8:]
        else: continue
        out.append(row)
    return out


def corrected_contract(version):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.-]+)?", version)
    if match is None:
        raise ValueError("expected a release version such as 1.1.0")
    return tuple(map(int, match.groups())) >= (1, 1, 0)


def is_stateless(command, version):
    return command == "replay" or command == "reproduce" and corrected_contract(version)


def protocol_byte_frames():
    """Representative protocol bytes, including opaque security records.

    These are deliberately not authenticated TLS/SSH sessions. Application
    behavior is qualified separately by the live suite's independent peers.
    """
    cmac, smac = STATELESS_MACS
    frames = []

    def tcp(port, payload, reverse=False, ipv6=False):
        client, server = (C6, S6) if ipv6 else (C4, S4)
        src, dst, sp, dp = (server, client, port, 41000) if reverse else (client, server, 41000, port)
        body = struct.pack("!HHIIBBHHH", sp, dp, 1000 + len(frames), 9000, 80, 24, 65535, 0, 0) + payload
        frames.append(packet(src, dst, 6, transport(src, dst, 6, body, 16), cmac, smac, reverse))

    tcp(80, b"GET /capture HTTP/1.1\r\nHost: lab.invalid\r\n\r\n")
    tcp(53, struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY)
    for level, port in ((4, 1883), (5, 1884)):
        body = b"\x00\x04MQTT" + bytes([level, 2, 0, 60])
        if level == 5:
            body += b"\x00"  # no MQTT 5 CONNECT properties
        body += b"\x00\x0ccaptured-lab"
        tcp(port, b"\x10" + bytes([len(body)]) + body)
    tcp(502, bytes.fromhex("000100000006010300000001"))

    def dnp_crc(data):
        crc = 0
        for byte in data:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0xA6BC if crc & 1 else 0)
        return struct.pack("<H", (~crc) & 0xffff)
    # Unconfirmed link data, first/last transport and application READ.
    user = bytes.fromhex("c0c0013c0106")
    header = bytes.fromhex("0564") + bytes([5 + len(user), 0xc4, 1, 0, 0, 4])
    tcp(20000, header + dnp_crc(header) + user + dnp_crc(user))
    tcp(21, b"220 Captured FTP service\r\n", reverse=True)
    tcp(20, b"captured FTP data bytes", reverse=True)
    tcp(21, b"AUTH TLS\r\n")
    opaque_tls = bytes.fromhex("1703030020") + bytes(range(32))
    tcp(21, opaque_tls)
    tcp(990, opaque_tls, reverse=True)
    tcp(22, b"SSH-2.0-CapturedLab\r\n", reverse=True)
    tcp(22, bytes(range(32)))
    tcp(19001, b"captured IPv6 TCP bytes", ipv6=True)
    body = struct.pack("!HHHH", 41001, 19000, 8 + len(UDP_REQ), 0) + UDP_REQ
    frames.append(packet(C6, S6, 17, transport(C6, S6, 17, body, 6), cmac, smac))
    return frames


def stateless_fixture(path, version="1.0.1"):
    """Opaque mixed Ethernet bytes; no application/security semantics claimed."""
    cmac, smac = STATELESS_MACS
    frames = []
    for reverse, payload in ((False, b"plain TCP bytes"), (True, bytes.fromhex("1703030020") + bytes(range(32)))):
        src, dst, sp, dp = (S4, C4, 443, 40000) if reverse else (C4, S4, 40000, 443)
        body = struct.pack("!HHIIBBHHH", sp, dp, 1000, 9000, 80, 24, 65535, 0, 0) + payload
        frames.append(packet(src, dst, 6, transport(src, dst, 6, body, 16), cmac, smac, reverse))
    for port, payload in ((53, DNS_QUERY), (19000, b"unknown UDP bytes")):
        body = struct.pack("!HHHH", 40001, port, 8 + len(payload), 0) + payload
        frames.append(packet(C4, S4, 17, transport(C4, S4, 17, body, 6), cmac, smac))
    echo = struct.pack("!BBHHH", 8, 0, 0, 4242, 1) + ECHO
    echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
    frames.append(packet(C4, S4, 1, echo, cmac, smac))
    echo = struct.pack("!BBHHH", 128, 0, 0, 4242, 1) + ECHO
    frames.append(packet(C6, S6, 58, transport(C6, S6, 58, echo, 2), cmac, smac))
    frames.append(smac + cmac + bytes.fromhex("88b5") + b"unknown Ethernet payload")
    if corrected_contract(version):
        frames.extend(protocol_byte_frames())
    frames = [frame.ljust(60, b"\0") for frame in frames]
    with Path(path).open("xb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            output.write(struct.pack("<IIII", 1700000000, i * 20000, len(frame), len(frame)) + frame)
    return frames


def ethernet_frames(path):
    data = Path(path).read_bytes()
    if len(data) < 24 or data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        raise ValueError("not a complete classic PCAP")
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError("stateless observation must be Ethernet")
    frames, offset = [], 24
    while offset < len(data):
        if offset + 16 > len(data): raise ValueError("truncated PCAP record")
        _, _, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured != original or captured < 14 or offset + captured > len(data):
            raise ValueError("truncated Ethernet frame")
        frames.append(data[offset:offset + captured])
        offset += captured
    return frames


def verify_stateless_report(report, fixture, capture, repeats, version, command="replay"):
    expected = ethernet_frames(fixture)
    observed = ethernet_frames(capture)
    if not expected or observed != expected * repeats:
        raise ValueError("independent stateless bytes/order/count differ")
    wanted = {"tool": "livewire", "version": version, "mode": "wire", "status": "wire",
              "completed": True, "verified": False, "passes": repeats, "framesPerPass": len(expected),
              "framesSent": len(observed), "captureDigest": "sha256:" + sha(fixture)}
    if corrected_contract(version):
        if command not in ("reproduce", "replay"):
            raise ValueError("not a stateless front door")
        wanted["command"] = command
    if any(type(report.get(k)) is not type(v) or report.get(k) != v for k, v in wanted.items()) or report.get("error"):
        raise ValueError("stateless report differs or claims verified application behavior")
    return len(observed)


def verify_wire_capture(fixture, capture, repeats):
    expected, observed = ethernet_frames(fixture), ethernet_frames(capture)
    if not expected or observed != expected * repeats:
        raise ValueError("independent wire bytes/order/count differ")
    return len(observed)


def verify_wire_report(report, fixture, repeats, version):
    frame_count = len(ethernet_frames(fixture))
    if report.get("version") != version or report.get("attempts") != repeats or report.get("selectedPackets") != frame_count or report.get("captureDigest") != "sha256:" + sha(fixture) or report.get("outcome", {}).get("status") != "wire":
        raise ValueError("wire CLI summary differs from captured frames")
    totals, seen = {}, set()
    for session in report.get("sessions", []):
        key = (session.get("attempt"), session.get("sessionId"))
        if key in seen or type(key[0]) is not int or key[0] not in range(1, repeats + 1) or not key[1] or session.get("completed") is not True or session.get("verified") is not False or session.get("matched") is not False or session.get("status") != "wire" or session.get("mode") != "wire" or type(session.get("sent")) is not int or session["sent"] != session.get("packetCount"):
            raise ValueError("wire CLI session incomplete, duplicated or claims verification")
        seen.add(key)
        totals[key[0]] = totals.get(key[0], 0) + session["sent"]
    if totals != {attempt: frame_count for attempt in range(1, repeats + 1)}:
        raise ValueError("wire CLI per-attempt sent frame counts differ")


def verify_packets(name, rows, repeats):
    if name.startswith("icmp"):
        proto, request_type, reply_type = (58, 128, 129) if name == "icmp6" else (1, 8, 0)
        request = [p for p in rows if p["proto"] == proto and p.get("type") == request_type and p["payload"] == ECHO]
        reply = [p for p in rows if p["proto"] == proto and p.get("type") == reply_type and p["payload"] == ECHO]
        if len(request) < repeats or len(reply) < repeats: raise ValueError("independent ICMP request/reply count too small")
        return len(request), len(reply)
    if name in ("stateful-tcp", "transport-tcp"):
        requests, replies = {}, {}
        for p in rows:
            if p["proto"] != 6 or not p.get("payload"): continue
            streams = requests if p["src"] == C4 else replies if p["src"] == S4 else None
            if streams is None: continue
            port = p["sport"] if p["src"] == C4 else p["dport"]
            stream = streams.setdefault(port, {})
            for i, value in enumerate(p["payload"]): stream[(p["seq"] + i) & 0xffffffff] = value
        def matches(streams, expected):
            return sum(expected in bytes(b for _, b in sorted(s.items())) for s in streams.values())
        count, responses = matches(requests, TCP_REQ), matches(replies, TCP_RESP)
        if count < repeats or (name == "stateful-tcp" and responses < repeats): raise ValueError("independent TCP byte streams incomplete")
        return count, responses
    port, expected = (53, DNS_QUERY) if name == "dns-udp" else (19000, UDP_REQ) if name == "udp" else (19003, WIRE_REQ)
    request = [p for p in rows if p["proto"] == 17 and p.get("dport") == port and p["src"] == C4]
    reply = [p for p in rows if p["proto"] == 17 and p.get("sport") == port and p["src"] == S4]
    if name == "dns-udp":
        request = [p for p in request if p["payload"][2:] == expected[2:]]
        reply = [p for p in reply if p["payload"][2:] == dns_reply(expected)[2:]]
    else:
        request = [p for p in request if p["payload"] == expected]
        reply = [p for p in reply if p["payload"] == UDP_RESP] if name == "udp" else reply
    if len(request) < repeats or (name != "wire" and len(reply) < repeats): raise ValueError("independent UDP request/reply count too small")
    return len(request), len(reply)


class Lab:
    def __init__(self, args):
        self.args = args
        self.out = Path(args.output).resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        token = uuid.uuid4().hex[:10]
        self.client, self.server = "lwc-" + token, "lws-" + token
        self.cif, self.sif = "vc" + token, "vs" + token
        self.owned_ns, self.children, self.handles = [], [], []
        self.transcript = self.out / "events.jsonl"
        self.server_log = self.out / "peer.jsonl"
        self.started = utc()
        self.binary_sha = sha(args.binary)
        self.checked_evidence = {}
        self.continuity = LabContinuity(args.version)
        self.results = {command: {name: {"name": name, "passes": 0, "failures": 0, "requestsObserved": 0, "responsesVerified": 0, "repeatedProcessPasses": 0, "cleanupVerified": False} for name in args.case} for command in args.command}

    def event(self, **values):
        with self.transcript.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"at": utc(), **values}, sort_keys=True) + "\n")

    def run(self, argv, **kw):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=kw.pop("timeout", 30), **kw)
        if result.returncode: raise RuntimeError("command failed: " + repr(argv) + "\n" + result.stdout + result.stderr)
        return result.stdout

    def spawn(self, argv, log):
        handle = open(log, "wb")
        self.handles.append(handle)
        child = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
        child.lab_log_handle = handle
        self.children.append(child)
        return child

    def setup(self):
        for namespace in (self.client, self.server):
            self.run(["ip", "netns", "add", namespace])
            self.owned_ns.append(namespace)
        self.run(["ip", "-n", self.client, "link", "add", self.cif, "type", "veth", "peer", "name", self.sif, "netns", self.server])
        for namespace, interface, v4, v6 in [(self.client, self.cif, C4, C6), (self.server, self.sif, S4, S6)]:
            self.run(["ip", "-n", namespace, "addr", "add", v4 + "/24", "dev", interface])
            self.run(["ip", "-n", namespace, "-6", "addr", "add", v6 + "/64", "dev", interface, "nodad"])
            self.run(["ip", "-n", namespace, "link", "set", interface, "up"])
            self.run(["ip", "-n", namespace, "link", "set", "lo", "up"])
        def mac(namespace, interface):
            info = json.loads(self.run(["ip", "-n", namespace, "-j", "link", "show", "dev", interface]))
            return bytes.fromhex(info[0]["address"].replace(":", ""))
        if len(self.args.command) == 1 and is_stateless(self.args.command[0], self.args.version):
            stateless_fixture(self.out / "mixed-frames.pcap", self.args.version)
            self.event(event="setup", clientNamespace=self.client, serverNamespace=self.server, scriptSha256=sha(__file__))
            return
        fixtures(self.out, mac(self.client, self.cif), mac(self.server, self.sif))
        self.spawn(["ip", "netns", "exec", self.server, sys.executable, str(Path(__file__).resolve()), "--serve", str(self.server_log)], self.out / "peer-process.log")
        deadline = time.monotonic() + 5
        while "ready" not in (self.out / "peer-process.log").read_text():
            if time.monotonic() > deadline: raise RuntimeError("packet peer did not start")
            time.sleep(0.02)
        self.event(event="setup", clientNamespace=self.client, serverNamespace=self.server, scriptSha256=sha(__file__))

    def execute(self, command, name, round_number):
        self.continuity.check_start(name, utc())
        if sha(self.args.binary) != self.binary_sha:
            raise RuntimeError("CLI binary changed during qualification")
        if is_stateless(command, self.args.version):
            return self.execute_stateless(command, round_number)
        prefix = self.out / ("%s-%s-%05d" % (command, name, round_number))
        capture = Path(str(prefix) + ".independent.pcap")
        capture_filter = "ether src 02:42:42:00:00:01" if name == "wire" else "ip or ip6"
        cap = self.spawn(["ip", "netns", "exec", self.server, "tcpdump", "--immediate-mode", "-U", "-n", "-i", self.sif, "-w", str(capture), capture_filter], str(prefix) + ".tcpdump.log")
        deadline = time.monotonic() + 5
        while not capture.exists() or capture.stat().st_size < 24:
            if cap.poll() is not None or time.monotonic() > deadline: raise RuntimeError("independent capture did not start")
            time.sleep(0.02)
        mode = "transport" if name == "transport-tcp" else "wire" if name == "wire" else "auto"
        argv = ["ip", "netns", "exec", self.client, str(Path(self.args.binary).resolve()), command, str(self.out / (name + ".pcap")), "-t", S6 if name == "icmp6" else S4, "-i", self.cif, "-n", "3", "-gap", "50ms", "-run-timeout", "20s", "-report", str(prefix) + ".report.json", "-actual-out", str(prefix) + ".actual.pcap"]
        # Datagram/echo cases exercise the public defaults. Packet-pattern TCP
        # and wire cases deliberately retain explicit advanced compatibility.
        if name in ("stateful-tcp", "transport-tcp", "wire"):
            argv += ["-mode", mode]
        if name == "wire":
            target_index = argv.index("-t")
            del argv[target_index:target_index + 2]
            actual_index = argv.index("-actual-out")
            del argv[actual_index:actual_index + 2]
            gap_index = argv.index("-gap")
            del argv[gap_index:gap_index + 2]
        if name not in ("wire", "transport-tcp"):
            argv += ["-strict-exit"]
        began, monotonic = utc(), time.monotonic()
        self.continuity.check_start(name, began)
        impaired = self.args.netem and name == "stateful-tcp"
        if impaired:
            self.run(["ip", "netns", "exec", self.client, "tc", "qdisc", "add", "dev", self.cif, "root", "netem", "delay", "5ms", "1ms", "loss", "2%", "reorder", "10%", "50%"])
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=25)
        finally:
            if impaired:
                self.run(["ip", "netns", "exec", self.client, "tc", "qdisc", "del", "dev", self.cif, "root"])
        Path(str(prefix) + ".cli.log").write_text(result.stdout + result.stderr, encoding="utf-8")
        time.sleep(0.05)
        cap.send_signal(signal.SIGINT)
        cap.wait(timeout=5)
        self.children.remove(cap)
        cap.lab_log_handle.close()
        self.handles.remove(cap.lab_log_handle)
        if result.returncode != 0: raise RuntimeError("CLI failed for %s/%s: %s" % (command, name, result.stdout + result.stderr))
        fixture = self.out / (name + ".pcap")
        requests, responses = (verify_wire_capture(fixture, capture, 3), 0) if name == "wire" else verify_packets(name, decode_pcap(capture), 3)
        report = json.loads(Path(str(prefix) + ".report.json").read_text())
        if report.get("attempts") != 3: raise RuntimeError("CLI did not execute all repeated attempts")
        if name == "wire": verify_wire_report(report, fixture, 3, self.args.version)
        rules = self.run(["ip", "netns", "exec", self.client, "iptables-save"])
        Path(str(prefix) + ".firewall.txt").write_text(rules, encoding="utf-8")
        if "livewire" in rules.lower() or "--tcp-flags" in rules: raise RuntimeError("TCP RST guard leaked after CLI exit")
        artifacts = [capture, Path(str(prefix) + ".report.json"), Path(str(prefix) + ".cli.log"),
                     Path(str(prefix) + ".tcpdump.log"), Path(str(prefix) + ".firewall.txt")]
        if name != "wire":
            artifacts.append(Path(str(prefix) + ".actual.pcap"))
        else:
            artifacts.append(fixture)
        for artifact in artifacts:
            ref = evidence_ref(self.out, artifact)
            self.checked_evidence[ref["path"]] = ref["sha256"]
        finished = utc()
        self.continuity.observe(name, began, finished)
        case = self.results[command][name]
        case["firstAt"] = case.get("firstAt", began)
        case["lastAt"] = finished
        case["passes"] += 1
        case["repeatedProcessPasses"] += 1
        case["requestsObserved"] += requests
        case["responsesVerified"] += responses
        case["cleanupVerified"] = True
        proof = {"fixture": fixture.name, "fixtureSha256": self.checked_evidence[fixture.name]} if name == "wire" else {}
        self.event(event="pass", command=command, case=name, round=round_number, started=began, finished=finished, repeat=3, cleanupVerified=True, requests=requests, responses=responses, elapsedSeconds=round(time.monotonic() - monotonic, 4), impairment="netem delay 5ms 1ms loss 2% reorder 10% 50%" if impaired else "none", independentCapture=capture.name, captureSha256=self.checked_evidence[capture.name], report=Path(str(prefix) + ".report.json").name, reportSha256=self.checked_evidence[Path(str(prefix) + ".report.json").name], **proof)
        print(json.dumps({"command": command, "case": name, "round": round_number, "passes": case["passes"]}), flush=True)

    def execute_stateless(self, command, round_number):
        prefix = self.out / ("%s-mixed-frames-%05d" % (command, round_number))
        capture = Path(str(prefix) + ".independent.pcap")
        fixture = self.out / "mixed-frames.pcap"
        capture_filter = " or ".join("ether src " + ":".join("%02x" % b for b in mac) for mac in STATELESS_MACS)
        cap = self.spawn(["ip", "netns", "exec", self.server, "tcpdump", "--immediate-mode", "-U", "-n", "-i", self.sif, "-w", str(capture), capture_filter], str(prefix) + ".tcpdump.log")
        deadline = time.monotonic() + 5
        while not capture.exists() or capture.stat().st_size < 24:
            if cap.poll() is not None or time.monotonic() > deadline: raise RuntimeError("independent stateless capture did not start")
            time.sleep(0.02)
        report_path = Path(str(prefix) + ".report.json")
        output_path = Path(str(prefix) + ".cli.log")
        began = utc()
        self.continuity.check_start("mixed-frames", began)
        argv = ["ip", "netns", "exec", self.client, str(Path(self.args.binary).resolve()), command, "-in", str(fixture), "-i", self.cif, "-n", "3", "-report", str(report_path)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=25)
        output_path.write_text(result.stdout + result.stderr, encoding="utf-8")
        time.sleep(0.05)
        cap.send_signal(signal.SIGINT)
        cap.wait(timeout=5)
        self.children.remove(cap)
        cap.lab_log_handle.close()
        self.handles.remove(cap.lab_log_handle)
        if result.returncode != 0: raise RuntimeError("stateless CLI failed: " + result.stdout + result.stderr)
        frames = verify_stateless_report(json.loads(report_path.read_text()), fixture, capture, 3, self.args.version, command)
        rules = self.run(["ip", "netns", "exec", self.client, "iptables-save"])
        firewall = Path(str(prefix) + ".firewall.txt")
        firewall.write_text(rules, encoding="utf-8")
        if "livewire" in rules.lower() or "--tcp-flags" in rules: raise RuntimeError("stateless replay left a firewall guard")
        for artifact in (fixture, capture, report_path, output_path, firewall, Path(str(prefix) + ".tcpdump.log")):
            ref = evidence_ref(self.out, artifact)
            self.checked_evidence[ref["path"]] = ref["sha256"]
        finished = utc()
        self.continuity.observe("mixed-frames", began, finished)
        case = self.results[command]["mixed-frames"]
        case["firstAt"] = case.get("firstAt", began)
        case["lastAt"], case["cleanupVerified"] = finished, True
        case["passes"] += 1
        case["repeatedProcessPasses"] += 1
        case["framesObserved"] = case.get("framesObserved", 0) + frames
        self.event(event="pass", command=command, case="mixed-frames", round=round_number, started=began, finished=finished, repeat=3, cleanupVerified=True, framesObserved=frames, requests=0, responses=0, fixture=fixture.name, fixtureSha256=self.checked_evidence[fixture.name], independentCapture=capture.name, captureSha256=self.checked_evidence[capture.name], report=report_path.name, reportSha256=self.checked_evidence[report_path.name], output=output_path.name, firewall=firewall.name, firewallSha256=self.checked_evidence[firewall.name])
        print(json.dumps({"command": command, "case": "mixed-frames", "round": round_number, "passes": case["passes"], "frames": frames}), flush=True)

    def cleanup(self):
        clean = True
        for child in reversed(self.children):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
        for namespace in reversed(self.owned_ns):
            try: self.run(["ip", "netns", "del", namespace])
            except Exception as e:
                clean = False
                self.event(event="cleanup-error", detail=str(e))
        remaining = self.run(["ip", "netns", "list"])
        if any(namespace in remaining.split() for namespace in self.owned_ns): clean = False
        for handle in self.handles: handle.close()
        self.event(event="cleanup", verified=clean)
        return clean

    def finish(self, interrupted, clean):
        evidence_error = None
        try:
            evidence = collect_evidence(self.out, self.checked_evidence)
        except (OSError, ValueError) as e:
            evidence_error, interrupted = e, True
            self.event(event="evidence-error", detail=str(e))
            # Retain the hashes checked at pass time even if an artifact was
            # deleted or modified. The failed run remains reviewable and can
            # never qualify using replacement evidence.
            evidence = [{"path": name, "sha256": digest} for name, digest in sorted(self.checked_evidence.items())]
            evidence.append(evidence_ref(self.out, self.transcript))
        for command, cases in self.results.items():
            doc = {"schemaVersion": 1, "version": self.args.version, "suite": "stateless" if is_stateless(command, self.args.version) else "packet", "platform": "linux-amd64", "environment": "Linux isolated owned network namespaces and veth; software peers; no physical NIC qualification", "command": command, "binarySha256": self.binary_sha, "sourceDigest": self.args.source_digest, "started": self.started, "finished": utc(), "interrupted": interrupted, "cleanupVerified": clean, "cases": list(cases.values()), "evidence": evidence}
            (self.out / (command + ".run.json")).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        if evidence_error is not None:
            raise evidence_error


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        serve(sys.argv[2])
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True)
    p.add_argument("--output", required=True, help="new directory for immutable evidence")
    p.add_argument("--source-digest", required=True)
    p.add_argument("--version", required=True, help="expected executable release version")
    p.add_argument("--command", choices=["live", "reproduce", "replay"], action="append", help="live packet suite by default; reproduce/replay each require a separate stateless run (pre-1.1 versions retain historical routing)")
    p.add_argument("--case", choices=CASES + ["mixed-frames"], action="append", help="targeted smoke checks; omit for full qualification")
    p.add_argument("--duration", type=float, default=7200)
    p.add_argument("--round-gap", type=float, default=5)
    p.add_argument("--netem", action="store_true", help="exercise stateful TCP with namespace-local loss, jitter, and reordering")
    args = p.parse_args()
    if any(not math.isfinite(value) or value < 0 for value in (args.duration, args.round_gap)):
        p.error("duration and round gap must be finite and nonnegative")
    try:
        corrected = corrected_contract(args.version)
    except ValueError as error:
        p.error(str(error))
    if corrected and args.round_gap > LabContinuity.MAX_IDLE:
        p.error("round gap exceeds qualification continuity limit of 60 seconds")
    args.command = args.command or (["live"] if corrected else ["live", "reproduce"])
    if len(set(args.command)) != len(args.command): p.error("duplicate commands are not separate runs")
    if any(is_stateless(command, args.version) for command in args.command):
        if len(args.command) != 1 or args.case not in (None, ["mixed-frames"]): p.error("stateless reproduce/replay requires a separate run containing only mixed-frames")
        args.case = ["mixed-frames"]
        if args.netem: p.error("stateless byte-fidelity checks do not use loss/reordering impairment")
    else:
        args.case = args.case or CASES
        if "mixed-frames" in args.case: p.error("mixed-frames requires a stateless reproduce/replay command")
    if os.geteuid() != 0: p.error("requires root for owned network namespaces and raw packet capture")
    lab = Lab(args)
    interrupted, clean = True, False
    def terminate(_signum, _frame):
        raise KeyboardInterrupt("packet lab terminated")
    previous_term = signal.signal(signal.SIGTERM, terminate)
    try:
        lab.setup()
        round_number = 0
        while True:
            round_number += 1
            for command in args.command:
                for name in args.case:
                    try: lab.execute(command, name, round_number)
                    except Exception as e:
                        lab.results[command][name]["failures"] += 1
                        lab.event(event="failure", command=command, case=name, detail=str(e))
                        raise
            def complete(c):
                start = datetime.datetime.fromisoformat(c["firstAt"].replace("Z", "+00:00"))
                end = datetime.datetime.fromisoformat(c["lastAt"].replace("Z", "+00:00"))
                return c["passes"] >= 3 and (end - start).total_seconds() >= args.duration
            if all(complete(c) for cases in lab.results.values() for c in cases.values()): break
            time.sleep(args.round_gap)
        interrupted = False
    finally:
        try:
            clean = lab.cleanup()
            lab.finish(interrupted, clean)
        finally:
            signal.signal(signal.SIGTERM, previous_term)
    if not clean: raise RuntimeError("lab cleanup was not verified")


if __name__ == "__main__":
    main()
