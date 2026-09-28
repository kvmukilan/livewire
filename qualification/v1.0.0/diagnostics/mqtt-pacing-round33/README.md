# Excluded MQTT pacing diagnostic

This is a retained failure, not passing qualification. The superseded Linux `live` application soak failed `mqtt311-tls` in round 33 after about 19 minutes. Its exact old source and executable hashes, start/end times, selected case totals, and hashes of the original run report/transcript are in `diagnostic-identity.json`.

The independent peer transcript records one rejected exchange (`EOF`) and zero active connections after cleanup. Secure attempt 1 timed out waiting for message 1; attempts 2 and 3 matched. The original command output correctly reported an intermittent result and exited unsuccessfully. The three per-attempt reports and the single relevant transcript entry are retained; fixture captures, key logs, private keys, and unrelated rounds are excluded.

The cause was a pacing deadline race. `WaitUntil` checked that the capture target was still ahead, then passed `time.Until(target)` to the reader. If that duration had become nonpositive, the reader interpreted it as an unspecified timeout and substituted its 30-second default. The small independent deadline probe reproduced a requested socket deadline about 100 ms beyond the target (the reader's polling interval); this demonstrates the escaped pacing deadline without making the probe wait 30 seconds.

The fix carries the absolute capture/exchange deadline into the reader. Pacing expiry is recognized only for peer-read deadline errors, so maintenance, generated-control writes, and journal failures retain their original error meaning. The public reader's default for an explicitly unspecified timeout remains unchanged. Source binding for the after-fix probes is recorded separately from the failed binary.

The same probe completed 120,000 tiny-deadline attempts without reproducing the defect on both Windows and Linux after the fix. Those focused diagnostic results are not a replacement for renewed full gates or two-hour soaks. The original probe source is retained as `.go.txt` to avoid introducing a new Go package; copy it under the repository's ignored `coverage/` directory before running `GOTOOLCHAIN=go1.26.7 go run coverage/<probe>.go`.

Retained text is UTF-8 without BOM with LF line endings. `index.json` records hashes after normalization and original hashes for copied files. None of these files is referenced as a passing software-lab run or check.
