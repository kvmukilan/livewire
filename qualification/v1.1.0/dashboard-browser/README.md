# Supplemental rendered dashboard QA

The frozen v1.1.0 Windows binary passed automated rendered-browser checks in
installed Playwright Chromium. The accompanying JSON records exact source and
binary pins, actual UTC times, browser version, desktop/mobile viewports,
independent synthetic-peer observations and screenshot hashes.

The dashboard selects captures from its working directory; it has no upload
control. Both Inspect & preview actions sent nothing. Keyless TLS completed a
fresh verified handshake with zero application bytes, showed amber application
incomplete, and retained false application completion/verification/matching.
Embedded PCAPNG TLSK secrets enabled a verified TLS 1.3 HTTP replay without an
external key-log file. A real wrong-host certificate check failed and remained
red; this deliberate negative test is explicitly distinguished from an
unexpected peer error.

This is supplemental automated browser evidence with model visual inspection,
not human acceptance, physical-device qualification, a two-hour soak or a claim
that publication has completed. The authoritative release manifest, hosted lab
reports and independent validators remain separate gates.

Only task-owned resources were checked: ten process identities and three
listeners were absent afterward. The browser and synthetic fixture exited
normally. The idle hidden dashboard lacked a console, so its exact owned PID
was force-stopped after a bounded graceful-stop attempt. This run therefore
does not establish graceful dashboard shutdown behavior.

The original private evidence is preserved. The JSON was constructed from an
explicit field allowlist, after rechecking every private summary-bound artifact
hash and all positive/negative outcomes. It omits raw captures, embedded
secrets, certificates, executable helpers, full API payloads, interface
inventory, process IDs and listener ports. Screenshot hashes identify privately
retained images; no images or executable code are included in this bundle.
The repository exporter content guard accepted the retained JSON and README.
All retained files are UTF-8 without BOM and use LF newlines.
