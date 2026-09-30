# Version 1.1 command correction

## Two commands, two behaviors

The intended contract is now explicit: **`live` is stateful application replay;
`reproduce` is stateless packet replay.** Neither requires a mode flag.

| Command | Behavior | Evidence |
|---|---|---|
| `live capture.pcap -t device` | Opens fresh connections; OS TCP and supported adapters maintain live state. TLS plaintext is recovered with matching capture keys, then sent over a new verified session. | Compared live responses, differences and incomplete exchanges. |
| `reproduce capture.pcap -i interface` | Injects the recorded frames unchanged, including both captured directions, in capture order with selected pacing. | Actual send counts; never a response-equivalence claim. |
| `replay ...` | Compatibility alias for stateless `reproduce`. | The same packet evidence and limitations. |

`reproduce` can send a PCAP containing TLS ciphertext as recorded bytes without
a key log. It cannot use those old bytes to negotiate a new TLS session. Use
`live` with matching capture key material when the target must understand the
recorded application requests.

## Migration from 1.0.x

The earlier implementation incorrectly gave `live` and `reproduce` the same
application workflow. Version 1.1 corrects that command distinction.

```sh
# 1.0.x application workflow:
# livewire reproduce issue.pcap -t 192.168.1.50

# 1.1 application workflow:
livewire live issue.pcap -t 192.168.1.50

# 1.1 stateless packet preview and transmission:
livewire reproduce issue.pcap -dry-run
livewire reproduce issue.pcap -i eth0 -report packets.json
```

Application-only options on `reproduce`, including `-t`, `-keylog`, `-resume`
and explicit application modes, are rejected before capture loading or network
access, with instructions to use `live`. This prevents old application scripts
from silently becoming packet injection. Stateless sends require an explicit
interface; `-dry-run` never opens a sender. `live -in` keeps its historical
dry-run/packet controls unless explicit secure inputs select fresh sessions.

Use `rewrite` separately for static captured addresses or ports. Stateless
reproduction does not retarget packets or track TCP state. Captured pacing is
best-effort scheduling, not a guarantee of identical network conditions.

## Qualification and publication

The changed source requires fresh [qualification](V1_QUALIFICATION.md).
Application `live` is checked against independent Windows/Linux protocol peers.
Linux virtual networks check the advanced packet routes and independent
stateless `reproduce` and `replay` runs. Every required case must span two hours
of successful actual CLI executions, with exact source and binary hashes,
retained evidence, zero failures and verified cleanup.

The [release audit](RELEASE_AUDIT.md) records completed checks and remaining
gates. Historical v1.0.0 and v1.0.1 tags, artifacts and qualification are retained
unchanged; their results do not qualify the corrected source.

The previous [v1.0.1 follow-up record](https://github.com/kvmukilan/livewire/blob/v1.0.1/docs/V1_FOLLOWUP.md)
documents the former contract. Physical NIC/DUT tests, native Linux arm64
runtime and human-pilot qualification remain separate from software labs.

## Website

The static website under `website/` provides installation, command workflows,
secure replay, supported protocols and version-pinned release downloads.
Capture files, key logs and credentials stay on the operator's computer. Its
release metadata must be promoted only after the linked binary is published
and verified, so website examples cannot claim unreleased command behavior.
