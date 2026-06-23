# Progress so far

A Windows (WinForms, .NET 10) single-exe app that scans files/folders with VirusTotal.

## Built and working
- Scan via right-click (HKLM context menu, admin), drag-drop, GUI, or terminal (CLI).
- **Keyless engine (default):** validly-signed files (Authenticode, embedded + catalog) skip VT
  entirely; everything else is looked up through a hidden WebView2 driving VT's public GUI (no
  key, no quota) with interactive reCAPTCHA solving; API (Polly) is the fallback.
- Multi API key rotation + quota dashboard; waits (does not exit) when all keys are exhausted.
- Local hash cache / history (`cache.json`, summary only) next to the exe; first-seen/rarity.
- User-configurable verdict categories (detection-count thresholds + names + colors).
- Quarantine renames to `.VIRUS`, gated by a reflection-based "don't ask again" confirm system.
- Tray + start-with-Windows; resume interrupted scans (ask / auto); global exception logging.
- Both single-exe publish profiles (framework-dependent ~2.7 MB, self-contained ~47.9 MB).

## Autonomous loop (this branch: claude/autoloop)
- Ideas queue in `Brainstorm/` (FIFO Inbox -> Applied/Rejected).
- Coding principles in `docs/coding-principles.txt` (followed strictly: English everywhere in
  code/UI/comments, central management, null-safety, Polly + CancellationToken wrapping).
- Lessons in `öğrenilen değerli şeyler.md`.

## Done in the loop so far
- Parallel-upload setting (separate upload semaphore from the scan concurrency).
- Major/minor engine consensus ("who flagged it"): editable major-engine set, shown in the
  detail pane + CLI + cache; surfaces likely false positives (verified on ski32.exe: 1 major / 5 minor).
- Detail pane shows all engine results by default; community votes (harmless/malicious), toggleable.
- CLI `--report <html|json|txt>` + `--fail-on <N>` exit-code gate (shared `ReportWriter`).
- GUI "Export report (HTML/JSON/text)" button.
- Detection-name normalization → most-common malware family label (detail + CLI + cache).
- Download-origin signal from the NTFS Zone.Identifier stream (detail pane).
- Verdict re-check sweep: keyless re-lookup of cached files older than a configurable period,
  one batch confirm, reports verdict changes (GUI button + setting).
- Folder rollup dialog: per-folder verdict breakdown, threats worst-first.
- Size pre-filter: skip files over a configurable MB cap, shown as skip-ledger rows.

## Not yet done (in the queue)
Localization EN/TR (next), community comments, quota-exhausted 3-option, spread resilient
recovery chains, behavior/sandbox summary, archive expansion, expected-hash, scheduled sweep,
find-all-copies, folder neighbors, integrity baseline, scan running processes, context menus
everywhere, UI polish/emojis.
