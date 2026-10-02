"""Minimal Modbus/TCP lab for recording a replay clip. No deps.

python modbus_lab.py server [port]   -- answers FC3 (read holding regs) and FC6 (write single reg), unit 1
python modbus_lab.py client [port]   -- a short, realistic operator session: 4 reads, 1 write, 1 read
"""
import socket, struct, sys, threading, time

PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 502
REGS = [0] * 64
# a little "process": tank level 0..100 at reg 0, setpoint at reg 1, pump state at reg 2, pressure at reg 3
REGS[0], REGS[1], REGS[2], REGS[3] = 61, 70, 1, 312

def handle(conn):
    try:
        while True:
            hdr = conn.recv(7)
            if len(hdr) < 7:
                return
            txid, proto, length, unit = struct.unpack(">HHHB", hdr)
            pdu = conn.recv(length - 1)
            fc = pdu[0]
            if fc == 3:
                addr, qty = struct.unpack(">HH", pdu[1:5])
                if qty < 1 or qty > 125 or addr + qty > len(REGS):
                    rsp = bytes([fc | 0x80, 0x02])
                else:
                    data = b"".join(struct.pack(">H", REGS[addr + i]) for i in range(qty))
                    rsp = bytes([3, len(data)]) + data
            elif fc == 6:
                addr, val = struct.unpack(">HH", pdu[1:5])
                if addr >= len(REGS):
                    rsp = bytes([fc | 0x80, 0x02])
                else:
                    REGS[addr] = val
                    rsp = pdu[:5]
            else:
                rsp = bytes([fc | 0x80, 0x01])
            conn.sendall(struct.pack(">HHHB", txid, 0, len(rsp) + 1, unit) + rsp)
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        return
    finally:
        conn.close()

def server():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT)); s.listen(5)
    print(f"modbus server on 127.0.0.1:{PORT}", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

def req(sock, txid, pdu, unit=1):
    sock.sendall(struct.pack(">HHHB", txid, 0, len(pdu) + 1, unit) + pdu)
    hdr = sock.recv(7); _, _, ln, _ = struct.unpack(">HHHB", hdr)
    return sock.recv(ln - 1)

def client():
    s = socket.create_connection(("127.0.0.1", PORT))
    time.sleep(0.2)
    for i, (fc, a, q) in enumerate([(3, 0, 4), (3, 0, 4), (3, 2, 1), (3, 0, 4)], start=1):
        r = req(s, i, struct.pack(">BHH", fc, a, q)); print("read", a, q, r.hex()); time.sleep(0.25)
    r = req(s, 5, struct.pack(">BHH", 6, 1, 75)); print("write setpoint 75", r.hex()); time.sleep(0.25)
    r = req(s, 6, struct.pack(">BHH", 3, 0, 4)); print("read", 0, 4, r.hex()); time.sleep(0.2)
    s.close()

if __name__ == "__main__":
    server() if sys.argv[1] == "server" else client()
