# Security Policy

## Supported version

Security fixes are currently made for the v0.5 line.

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
- Keep the web server on `127.0.0.1`. It has no application authentication and
  must not be exposed directly to an untrusted network.
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

- Store key logs and private keys outside the capture/artifact directory.
- Restrict permissions on the capture directory and delete secrets according to
  your retention policy.
- Review PCAP/PCAPNG payloads before sharing; evidence may contain replayed
  credentials even though metadata does not.
- Use `livewire bundle` or the dashboard bundle action. The archive recursively
  redacts secret-shaped report fields and references evidence by name, size, and
  SHA-256 only; it never embeds packet bytes, the key log, an SSH key, or the
  original capture.

## Capture trust boundary

PCAPs, PCAPNGs, topology/scenario JSON, and adapter rule packs are untrusted
input. Livewire bounds record and framing sizes, rejects malformed structures,
does not execute rule-pack scripts, and tests parsers with malformed and fuzzed
input. Analyze unknown captures without privileges before an on-wire run.

## Release verification

A release candidate is not cleared for production-adjacent use until it passes:

- module verification, unit tests, vet, and the race detector;
- Go 1.25 and current stable Go builds;
- Linux amd64/arm64 and Windows amd64 builds;
- elevated Linux and Windows one-sided hardware smoke tests;
- a two-interface DUT smoke test with cancellation and guard cleanup;
- opening dual-interface PCAPNG evidence in Wireshark;
- manual confirmation that reports contain no supplied secret values.
