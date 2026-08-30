# Livewire Feature Audit (historical v0.5.0 review)

> Historical record: this document describes the v0.5.0 command surface and
> its follow-up cleanup. For the current v0.8.0 security, replay orchestration,
> FTP/FTPS, CI, and release disposition, see `RELEASE_AUDIT.md`; code pointers below are not a
> current inventory.

**Scope:** every user-facing command in `cmd/livewire/` and every package under
`internal/`, judged against the project's own bar — *works for a non-technical
peer (operator / field engineer) with smart defaults and almost no flags.*

**Method:** read the code, traced imports for reachability, counted flags,
checked for tests, and cross-checked each command against the four docs
(`README.md`, `DOCUMENTATION.md`, `WINDOWS-QUICKSTART.md`, `REPRODUCE.md`).

**Headline:** the core capture → check → reproduce path is genuinely strong
and honest about its limits. The peer-facing `reproduce` command and
`REPRODUCE.md` are the product's best assets. The friction was at the edges:
one dead command, one empty package, some dead internal functions, a real
version-drift bug in the web dashboard, and a front-door (`livewire` with no
args) that dumped 16 commands flat with no guidance toward the two a peer
actually needs.

**Status:** every item in §4 is now implemented — see §5 and §6. The front door
shows five commands, one flag vocabulary spans the whole CLI, and `reproduce`
grew an iterations feature for intermittent faults.

---

## 1. Command inventory & verdicts

Flag counts are the *defined* flags; most are hidden behind good defaults.
"Docs" = number of the four doc files that mention the command.

| Command | Flags | Tests | Docs | Verdict | One-line reason |
|---|---:|:---:|:---:|:---:|---|
| `reproduce` | 12 | yes | 4/4 | **KEEP** | Flagship. Interactive, plain-language `-under-load`/`-exact-tcp` aliases hide the fidelity profiles; only `-t`/`-i`/`-n` are peer-facing. |
| `analyze` | 5 | — | 3/4 | **KEEP** | Clean offline preflight + coverage plan; touches no interface. |
| `info` | 1 | — | 4/4 | **KEEP** | Read-only capture summary; cross-references `convert -reassemble`. |
| `ifaces` | 0 | — | 4/4 | **KEEP** | Lists interfaces + Windows Npcap device names a peer must paste. |
| `capture` | 5 | — | 2/4 | **KEEP** | Record to pcap. (Minor: stops on `os.Interrupt` only, not SIGTERM.) |
| `convert` | 3 | — | 2/4 | **KEEP** | pcapng → pcap, optional fragment reassembly. |
| `bundle` | 3 | yes | 2/4 | **KEEP** | Redacted, digest-only support archive. Security-conscious. |
| `web` | 2 | (pkg) | 2/4 | **KEEP** | Localhost-default dashboard, embedded, no runtime deps. |
| `tls-replay` | 11 | yes | 3/4 | **KEEP** | Honest TLS retermination; requires key log, verifies certs by default. |
| `ssh-replay` | 10 | yes | 3/4 | **KEEP** | Honest SSH retermination. Self-registers via `init()` (ssh_cmd.go:24) — still shows in `usage()`, just easy to miss when auditing. |
| `lab` | 11 | (pkg) | 3/4 | **KEEP (advanced)** | Two-sided DUT replay. Needs hand-written topology JSON — genuinely a power-user tool, not a peer tool. |
| `live` | 18 | yes | 4/4 | **KEEP (advanced)** | The expert TCP engine that `reproduce` wraps. Jargon flags (`-raw-l4`, `-adaptive`, `-mode peer|rewrite|both`) are appropriate *here*. |
| `rewrite` | 14 | (pkg) | 2/4 | **KEEP (advanced)** | tcprewrite-style static edits. Power-user. |
| `replay` | 8 | — | 2/4 | **KEEP (advanced)** | tcpreplay-style stateless blast. Conceptually overlaps `live`. |
| `rstdrop` | 3 | (pkg) | 3/4 | **IMPROVE** | Escape-hatch: `live`/`reproduce` already arm the RST guard automatically. Docs say "use only with Scapy," yet it sits in the top-level list a peer sees first. |
| `prep` | 5 | (e2e) | **0/4** | **DEAD** | Writes a client/server classification cache that **nothing reads**. Undocumented everywhere. See §3. |
| `version` | 0 | — | — | **KEEP** | Prints the version. |

### Notes that shape the verdicts

- **`reproduce` is well-built for the audience.** With no flags it asks two
  plain questions (device IP, which connection) and pre-selects the connection
  on the device's subnet (reproduce.go:339-410). The fidelity profiles are
  hidden behind `--under-load` / `--exact-tcp` (reproduce.go:36-37, 77-82).
  This is the model the rest of the tool should aspire to.
- **`verdict.go` is the gold standard for peer output** — plain-language
  "SAME AS THE RECORDING / DIFFERENT / DID NOT COMPLETE" with an internal abort
  reason translated to a human sentence (verdict.go:66-80). Keep and imitate.
- **But the same `reproduce` run also prints `printCoverage`** (coverage.go:59-75),
  a dense expert table with columns `driver`, `fidelity`, `adapter`, and
  `printPreflight` findings full of jargon — "wire lanes", "snaplen-truncated",
  "ISNs", "synthesize a best-effort handshake" (preflight.go:72-133). A field
  engineer reads jargon and plain-language in the same output. See §4, item 6.

---

## 2. Package inventory & verdicts

Import prefix `github.com/kvmukilan/livewire`. No `TODO`/`FIXME`/`panic("not
implemented")` markers exist anywhere in `internal/`.

| Package | Reached by | Tests | Verdict |
|---|---|:---:|:---:|
| `wire` | nearly everything (foundational parse/edit) | yes | **KEEP** |
| `pcapio` | ~14 cmd files + engine/replay/webui | yes | **KEEP** |
| `engine` | live, reproduce, lab, analyze, webui | yes (7) | **KEEP** |
| `replay` | analyze, reproduce, lab, tls, ssh, webui | yes (5) | **KEEP** |
| `dissect` | reproduce, live, lab, tls (via adapters) | yes (4) | **KEEP** |
| `adapters` | analyze, reproduce, lab, tls, ssh, web | yes (3) | **KEEP** |
| `ipreasm` | convert; reproduce/lab transitively | yes (2) | **KEEP** |
| `units` | transitive (seq math) | yes | **KEEP** |
| `flow` | info; most cmds transitively | — | **KEEP** (no direct test — minor) |
| `backend` | capture, replay, reproduce, live, web | 1 | **KEEP** (only mock path is unit-tested) |
| `stateless` | replay, web | yes | **KEEP** |
| `hoststack` | rstdrop, web; live/lab transitively | yes (2) | **KEEP** |
| `edit` | rewrite | yes | **KEEP** |
| `runvars` | reproduce, tls, ssh, bundle, web | yes | **KEEP** |
| `supportbundle` | bundle, web | yes | **KEEP** |
| `livereplay` | live, reproduce, web | yes (2) | **KEEP** (one dead func — §3) |
| `sshreplay` | ssh-replay, web | yes | **KEEP** (one dead func — §3) |
| `tlsreplay` | tls-replay | yes (5) | **KEEP** (best-tested package) |
| `lab` | lab, web | yes (3) | **KEEP (complex)** — `runner.go` ~1000 lines, 30-field collector |
| `tui` | live (`-tui` only) | yes | **KEEP** — conceptually overlaps `webui` (two dashboards) |
| `webui` | web | 1 (thin) | **KEEP** — but has a real bug + duplication (§3, §4) |
| `classify` | **only** `prep` + one test | yes | **DEAD-adjacent** — serves only the dead `prep` (§3) |
| `driver` | **nothing** (empty directory) | — | **DEAD** — no `.go` files at all (§3) |

---

## 3. DEAD / orphaned code (evidence)

1. **`internal/driver/` is an empty directory.** No `.go` files, no importers
   anywhere in the repo. A confusing leftover for any maintainer. *(Removed —
   see §5.)*

2. **`prep` command + `internal/classify` are orphaned.** `prep` (prep.go)
   classifies packets client/server and writes a "tcpprep-style" cache via
   `classify.WriteCache`. **No production code ever reads that cache** —
   `classify.ReadCache` is called only from `cmd/livewire/e2e_test.go:108`.
   `internal/classify` is imported only by `prep.go` and that test. `prep`
   appears in **zero** documentation files (not the README table, not
   `DOCUMENTATION.md` §15). It is a legacy artifact from before `lab` handled
   two-sided replay via topology JSON. *(Removed — see §5.)*

3. **`livereplay.SendStateless` (livereplay.go:103) is dead** — no caller, no
   test; superseded by `internal/stateless`, which `webui/jobs.go` actually
   uses. *(Removed — see §5.)*

4. **`sshreplay.runOne` (reterminate.go:128) is dead** — production and tests
   use `runOneContext`. *(Removed — see §5.)*

5. **Test-only non-context wrappers** (not removed — harmless): `replay`,
   `tlsreplay.ReTerminate` / `DecryptFlow`, `sshreplay.ReTerminate` exist only
   to give tests a simpler signature than the `…Context` variants used in
   production. Fine to keep; noted for completeness.

---

## 4. Improvement plan (ranked by peer-impact ÷ effort)

Items marked **[done]** were implemented in this pass or its v0.8.0 follow-up.

1. **[done] Group the no-argument `usage()` output** (main.go). A peer who runs
   `livewire` sees 17 commands in a flat list mixing `reproduce` with
   `rstdrop`, `prep`, `rewrite`, `live`. Split into **Everyday** (reproduce,
   analyze, info, ifaces, capture, convert) vs **Advanced**, and point first-time
   users at `reproduce`. *Highest peer impact, lowest effort — it is the front
   door.*

2. **[done] Delete the empty `internal/driver/` directory.** Pure cleanup, zero
   risk.

3. **[done] Fix the web-dashboard version-drift bug.** `internal/webui`
   hard-codes `"0.5.0"` in three places (runs.go:181, runs.go:376,
   platform.go:183), independent of `const version` in main.go:9. The next
   release will silently emit stale versions in every web-generated report.
   Fixed by threading the real version in from the `web` command.

4. **[done] Remove the dead `prep` command and `internal/classify`.** Shrinks
   the command surface by one and deletes an entire orphaned package — directly
   serving the "few commands, no dead ends" goal.

5. **[done] Remove dead functions** `livereplay.SendStateless` and
   `sshreplay.runOne`.

6. **[done] Plain-language the output a peer sees during `reproduce`.**
   `printCoverage` (coverage.go) and the `printPreflight` findings
   (preflight.go) speak in "wire lanes / driver / fidelity / snaplen-truncated /
   ISNs." The verdict block (verdict.go) already proves the team can write for
   this audience — bring the coverage/preflight text to the same level, or hide
   the expert table behind a `--details` flag during `reproduce` while keeping
   it default-on for `analyze`. *High peer impact, medium effort (output only;
   no tests assert on this text).*

7. **[done] Unify the profile vocabulary in the docs.** `reproduce`'s own
   help teaches `--under-load` / `--exact-tcp`, but `REPRODUCE.md` (Step 2) and
   `WINDOWS-QUICKSTART.md` (§5) tell the same peer to use raw `--profile timing`
   / `--profile transport`. Two names for one concept. Pick the plain-language
   aliases in the peer docs. *(A docs-only edit; safe to make now.)*

8. **[done] De-duplicate `webui.runWebEntry` vs `runPlanEntry`.**
   `webui/runs.go:196` re-implements the exact Blocked→Wire→Semantic→UDP/ICMP→
   stateful dispatch tree of `cmd/livewire/plan_run.go:81`, with twin
   `findWebFlow`/`waitWeb` helpers. Two copies that must stay in sync — a latent
   drift bug. Extract the shared dispatch into `internal/replay` (or a new small
   package) and call it from both. *Medium effort; prevents future divergence.*

9. **[done] Demote `rstdrop` from the everyday surface.** It is only needed
   when an external injector (Scapy) is used; `live`/`reproduce` arm the guard
   automatically. It is now in the advanced group, off the front door entirely,
   and its `-h` text says so in three lines.

10. **[done] Comment the surprising secret rules.** `runvars.IsSecret`
    (runvars.go:26) hard-codes `mqtt.username` and `http.body` as secrets with
    no explanation — a maintainer will wonder why a username is redacted. One
    comment line.

11. **[done] Single-source the version.** Even after item 3, `bundle`'s
    `Version` and webui share a literal-ish version. Consider one exported
    `const Version` in a tiny `internal/build` package imported by both
    `cmd/livewire` and `internal/webui`, so a release bump touches one line.

---

## 5. Changes implemented in this pass

All changes verified with `go build ./...`, `go vet ./...`, and `go test ./...`.

- **`cmd/livewire/main.go`** — `usage()` now groups commands into *Everyday* and
  *Advanced* and leads with a one-line pointer to `reproduce`.
- **`internal/driver/`** — removed (was empty).
- **`internal/webui`** — added a package-level `Version` (default `"0.5.0"`) set
  from the `web` command; replaced the three hard-coded version literals with it.
- **`cmd/livewire/web.go`** — sets `webui.Version = version` before serving.
- **Removed dead code:** `cmd/livewire/prep.go`, `internal/classify/` (whole
  package), the `prep` entry in `main.go`, the `prep`/`classify` round-trip in
  `e2e_test.go`; `livereplay.SendStateless`; `sshreplay.runOne`.

## 6. Second pass: command simplification and iterations

Items 6, 7, and 9 from §4 were completed here, alongside two changes that go
beyond the original audit: a single flag vocabulary, and repeat-a-replay support
for intermittent faults.

### Command surface

- **Front door shows five commands.** `command` gained a `group`
  (`groupEveryday` / `groupAdvanced` / `groupCompat`); `usage()` prints only the
  everyday group and `usageAll()` prints all three. `livewire help --all` and
  `livewire help <command>` were added, and asking for help now exits 0 instead
  of reporting `flag: help requested` as a failure.
- **`info` + `analyze` merged into `check`** (item 6 in spirit): one command
  answers both "what is in this capture" and "can it be replayed". The counting
  loop was extracted from `cmdInfo` into `captureStats` / `scanCapture` /
  `printCaptureStats` so both paths share it. `info` and `analyze` remain as
  `groupCompat` commands with their exact previous behaviour and output.
- **Expert output is behind `-details`** (item 6): `reproduce` no longer prints
  `printPreflight` or the `printCoverage` table by default. Blockers are still
  always shown, in plain language, because they change what the result means.
- **Expert flags are behind `-all-flags`**: `printFlags` in the new `help.go`
  lists a chosen subset. `reproduce` shows 7 of its 23 options by default.
- **`rstdrop` demoted** (item 9) and its `-h` now explains that `reproduce` and
  `live` arm the same guard themselves.
- **`ssh-replay` moved into the `commands` table**, replacing its `init()`
  self-registration, so the whole surface reads in one place.

### One flag vocabulary

`-in`, `-i`, `-t`, `-n`, `-o`, `-live`, `-details` mean the same thing on every
command that has them. Every superseded spelling (`--to`, `--on`, `-iface`,
`-target`, `-out`, `-loop`, `-count`, `-ip`, `-dry-run`) is still registered
against the same variable, so nothing that worked before stopped working; they
are simply not listed by default. `cmd/livewire/vocabulary_test.go` asserts both
halves of that claim per command, including that each alias actually feeds its
canonical variable rather than parsing and being ignored.

Item 7 followed from this: the peer docs use `-under-load` / `-exact-tcp`, and
`DOCUMENTATION.md` §2.6 now says explicitly that they are the same two profiles
it calls `timing` and `transport`.

### Iterations

- **`internal/iterate`** is the new home for the loop, the per-attempt verdict
  classification, the plain-language summary, and `ShiftPort`. Both the CLI and
  the dashboard call it, so the two cannot drift on any of them — the mistake
  item 8 describes for the dispatch tree.
- **`-n` on `reproduce` and `live`**, plus an *Attempts* field on the dashboard's
  one-sided form, replay the whole plan N times and report a rate. A device that
  answers differently between attempts is reported as `INTERMITTENT`, which is a
  distinct finding from a clean pass or a clean failure.
- **`livereplay.Config.LocalPort`** was added, and the tuple rewriter's
  `LiveClient` port now comes from it rather than from the captured flow. Without
  that, every attempt after the first would present an identical four-tuple and
  ISN, get reset as a stale duplicate, and be misreported as a failure to
  reproduce. `internal/livereplay/localport_test.go` asserts the override reaches
  the backend, the RST guard rule, and the bytes actually sent.
- **Reports gained `attempts`, `outcome`, and a per-result `attempt`**, all
  `omitempty`, so a single run's report is byte-for-byte what it was before.
  A test asserts that directly.

### Also cleaned up

- `compileCoverage` (`coverage.go`, zero callers) removed.
- `capture` now stops on SIGTERM as well as Ctrl-C, matching every other command;
  previously a supervised capture lost its buffered tail on shutdown.
- The dashboard's artifact timestamps went to millisecond resolution, since two
  attempts finishing in the same second would previously collide on filename.

### v0.8.0 follow-up completed

Items 8, 10, and 11 are now closed. CLI and dashboard dispatch share
`internal/planexec`; the secret-classification rules explain why MQTT usernames
and HTTP bodies are protected; and `internal/buildinfo.Version` is the single
release-version source used by CLI, dashboard, reports, and bundles.
