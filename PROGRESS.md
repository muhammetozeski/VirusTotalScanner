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
- Parallel-upload setting; major/minor engine consensus ("who flagged it", editable set); all
  engines shown by default; community votes; detection-name → family label; download-origin
  (Zone.Identifier); behavior/capability summary (VT tags + threat label).
- Signature-vs-heuristic confidence (VT `method` field); plain-language Keep/Caution/Remove
  recommendation synthesizing all signals (detail pane + CLI).
- PE identity / impersonation card (version-resource vs Authenticode signer; filename masquerade).
- Verdict re-check sweep; folder rollup; size pre-filter; expected-hash verify (`--expect`).
- CLI `--report html/csv/json/txt` + `--fail-on N`; `--diff <baseline.json>` verdict-regression
  gate (`--fail-on-new`, `--fail-on-regression`); `--running`; `--verify-baseline`.
- IR set: quarantine; find-all-copies on disk (Everything `es`); scan running processes; folder
  neighbors; path-integrity baseline + drift; persistence hunt (Run/Startup/Tasks); family clusters.
- Scheduled folder sweep (Windows Task); archive (ZIP-family) member expansion; quota-exhausted
  3-option prompt; resilient WaitAsync (principle 43, built-in); trust-before-hash perf reorder.
- EN/TR localization system (Strings + LocManager + lang.en.xml + switcher; main screen migrated).
- Rich context menus + double-click; verdict row coloring + emojis.
- Keyless GUI: fixed the browser popping up with no captcha (invisible reCAPTCHA false-trigger).

## Not yet done (in the queue, ~8 items)
Community comments, finish string migration, full sandbox behaviours (network/dropped/MITRE),
7z/rar/msi/iso expansion, live Downloads watch (FileSystemWatcher), publisher continuity check,
verdict drift report, in-scan content dedup.
