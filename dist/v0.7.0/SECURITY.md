# Security Policy

## Supported version

Security fixes are currently made for the v0.7 line.

## Reporting a vulnerability

Do not include real credentials, key logs, private keys, authorization headers,
or unreviewed packet captures in a public issue. Contact the maintainer through
the private security-reporting channel configured for the repository. Include a
minimal synthetic reproducer when possible.

## Privilege and network boundary

Livewire can open raw packet interfaces, install temporary RST-suppression
rules, impersonate captured endpoints, and transmit arbitrary captured frames.
Run it only on networks and devices you are authorized to test.

- Prefer an isolated lab VLAN or namespace.
- Use a dedicated low-privilege account for offline analysis.
- Elevate only the live replay process and only for the duration of the run.
- Review topology mappings and the compiled coverage plan before transmitting.
- Keep the web server on `127.0.0.1`. Its CSRF and same-origin controls protect
  browser mutations but are not user authentication. A non-loopback bind is
  refused unless `-unsafe-listen` is supplied and must never be exposed directly
  to an untrusted network.
- Do not use `-insecure-skip-verify` outside an isolated TLS lab.
- Pin SSH host keys when the peer identity matters. An unpinned host key is a
  lab convenience, not authenticated peer identity.

Livewire cancellation is designed to interrupt receive waits and pacing and to
release packet interfaces and temporary RST guards. Operators should still
confirm host firewall state after a forced process termination or machine
failure.

## Secret handling

Passwords, TLS secrets, SSH credentials, authorization values, MQTT
credentials, private-key material, and key-log contents must never be written to
logs, JSON reports, PCAP metadata, or support bundles.

Variable names with common secret markers are automatically redacted and their
supplied values are scrubbed from report errors. This is defense in depth, not a
substitute for operator review: a packet payload may itself contain sensitive
application data.

- Store key logs and private keys outside the capture/artifact directory when
  using the CLI. Dashboard file selection is deliberately rooted to its
  configured directory, so use a private mode-0700 directory for dashboard FTPS.
- Restrict permissions on the capture directory and delete secrets according to
  your retention policy.
- Review PCAP/PCAPNG payloads before sharing; evidence may contain replayed
  credentials even though metadata does not.
- Use `livewire bundle` or the dashboard bundle action. The archive recursively
  redacts secret-shaped report fields and references evidence by name, size, and
  SHA-256 only; it never embeds packet bytes, the key log, an SSH key, or the
  original capture.

## Capture trust boundary

PCAPs, PCAPNGs, topology/scenario JSON, key logs, CA files, and adapter rule
packs are untrusted input. Livewire limits each record/block to 16 MiB, decoded
capture data to 512 MiB, record count to 1,000,000, and dashboard JSON bodies to
1 MiB. It validates capture structure before allocation, rejects malformed
framing and file escapes, does not execute rule-pack scripts, and fuzzes the
parsers. Analyze unknown captures without privileges before an on-wire run.

FTP active/passive endpoints are also untrusted. Livewire connects passive data
channels only to the authenticated control peer, rewrites active endpoints to a
fresh local listener, blocks ambiguous captured groupings, and never transmits
captured TLS ciphertext. FTPS uses a fresh verified TLS connection for every
protected channel.

## Release verification

A release candidate is not cleared for production-adjacent use until it passes:

- module verification, unit tests, vet, and the race detector;
- Go 1.25.14, the Go 1.26.7 release builder, and Go 1.27.x;
- Linux amd64/arm64 and Windows amd64 builds;
- `govulncheck`, `staticcheck`, high-confidence `gosec`, race, shuffled/repeated,
  fuzz-smoke, package coverage, Windows-runtime, and cross-build gates;
- byte-identical artifact regeneration, CycloneDX validation, ZIP smoke,
  SHA-256 verification, and GitHub provenance.

Physical NIC/device replay, a two-interface physical DUT run, native Linux
arm64 execution, and Authenticode publisher trust are disclosed verification
boundaries for v0.7.0 rather than automated publication blockers.

## Windows release trust

The v0.7.0 Windows executable and ZIP are not Authenticode-signed. Download only
from the official GitHub release, compare the file against `SHA256SUMS`, and
verify the GitHub artifact attestation before allowing an unknown publisher.
The setup helper separately pins the official WinDivert v2.2.2 archive by
SHA-256 and validates available upstream signatures.
