# Supplemental Modbus over TLS smoke

One local Linux process used the frozen v1.1.0 binary for three fresh,
server-authenticated TLS connections. The input PCAPNG contained matching TLSK
secrets. No external keylog argument or SSLKEYLOGFILE environment entry was
passed. An independent loopback peer checked two Modbus read requests per
connection and returned both responses in reverse order with split writes.
All six application responses were compared successfully; peer identity checks,
source/binary pins, and owned listener/connection cleanup passed.

This is a short supplemental check, not another two-hour qualification, mTLS,
the full Modbus Security standard, or a physical-device test. Captured TLS was
1.2 and all fresh connections negotiated TLS1.3 without resumption. The CLI's
responses field counts received groups; comparedResponses/observedResponses
count the two framed Modbus responses in each attempt.

Only the safe summary, exact CLI reports, and safe peer observations are here.
Captures, matching secrets, fixture certificate, raw invocation/log, and helper
remain private. The summary records the private original proof/execution/helper
hashes and its explicit metadata projection. All retained files passed the
existing qualification exporter credential/content screen before copying.
The first diagnostic attempt was retained privately after an incorrect private
assertion expected the group count to equal the framed-response count; all three
CLI attempts had succeeded. Its evidence was not relabeled as this passing run.

This supplement is separate from the five sustained software qualification runs.
