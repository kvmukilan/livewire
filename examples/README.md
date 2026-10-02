# Examples

A real capture and the lab that produced it, so livewire can be tried without
finding a device first.

## `modbus-session.pcap`

31 packets, one Modbus/TCP session: four reads of the holding registers, a write
to the setpoint, then a read back. Classic pcap, nanosecond timestamps, clean
handshake and close.

```sh
livewire check examples/modbus-session.pcap -details
```

That reports one TCP session on the `modbus-tcp` adapter at semantic fidelity.
Nothing is sent; `check` only reads the file.

## `modbus_lab.py`

A dependency-free Modbus/TCP server and client, standard library only, bound to
loopback. It answers function 3 (read holding registers) and function 6 (write
single register) on unit 1, over a 64-register map standing in for a small
process: tank level, setpoint, pump state, pressure.

To replay the capture against it:

```sh
python examples/modbus_lab.py server                           # terminal 1, listens on 502
livewire live examples/modbus-session.pcap -t 127.0.0.1        # terminal 2
```

which reports:

```
RESULT: completed=true matched=true sent=6 received=6
Summary: 1 same as recording, 0 different, 0 unverified, 0 wire-only, 0 did not complete.
```

Note that `-t` takes the device address and the port comes from the capture, so
the server has to listen on 502 — the port the session was recorded on. The
`host:port` form of `-t` is for fresh secure targets, not for overriding a plain
TCP port.

If the register the capture writes has already been changed, the replay instead
reports `matched=false` and names the differing values, which is the more useful
case: it tells you what drifted rather than only that something did.

The same server is a target for `livewire fuzz -target 127.0.0.1:502`, though
`livewire fuzz -demo` has a built-in target and needs no setup at all.

## Provenance

Both files are synthetic. The capture was recorded over loopback against the
script in this directory; no real device, network or credential is involved.
