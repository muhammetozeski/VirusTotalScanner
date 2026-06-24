# Öğrenilen değerli şeyler (hard-won lessons)

Bu dosyaya, çözmesi zor olan sorunları ve çözümlerini kaydediyorum ki bir daha aynı duvara
çarpmayalım. (Lessons learned: tricky problems and their solutions.)

---

## WebView2 reCAPTCHA-free VT data capture
- VT's `/gui/file/<hash>` page is an empty SPA shell; the data is fetched by the page's own JS
  from `/ui/files/<hash>`, which is reCAPTCHA-protected for raw requests but works inside a
  real Chromium (WebView2) session. Capture it via `CoreWebView2.WebResourceResponseReceived`
  (note: the arg type is `CoreWebView2WebResourceResponseView`, NOT `...Response`).

## Catalog signatures (Authenticode)
- Most in-box Windows binaries have NO embedded signature; they are catalog-signed. A bare
  `WINTRUST_FILE_INFO` verify returns `TRUST_E_NOSIGNATURE` for them. Must fall back to the
  catalog path: `CryptCATAdminAcquireContext2("SHA256")` + `CalcHashFromFileHandle2` +
  `CryptCATAdminEnumCatalogFromHash` + `WinVerifyTrust` with `WINTRUST_CATALOG_INFO`.

## WinForms analyzer WFO1000
- A public auto-property on a `Control`/`Form` subclass is treated as designer-serializable and
  fails the build (error). For code-only controls, use a public field instead.

## Tray start (--tray)
- `Application.Run(form)` exits immediately if the form is never shown. To start hidden in the
  tray: show the form with `Opacity=0 / Minimized / ShowInTaskbar=false`, then `Hide()` on the
  first `Shown` — the message loop stays alive.

## Single-instance test pollution
- A leftover running instance holds the single-instance mutex, so a new launch becomes the
  secondary and forwards+exits. Kill stragglers before testing launch behavior — but ASK the
  user first if the instance might be theirs.

## NTFS Zone.Identifier (download origin) read
- The "downloaded from the internet" mark is the `:Zone.Identifier` alternate data stream
  (`[ZoneTransfer]` INI: ZoneId 3=internet, plus ReferrerUrl/HostUrl). `File.Exists` on the ADS
  path is unreliable — instead `File.ReadAllText(path + ":Zone.Identifier")` and catch
  `FileNotFoundException` (no stream / not NTFS) as the "absent" case.

## Testing a GUI-subsystem exe from PowerShell
- `Start-Process -ArgumentList @("a","b c")` does NOT quote array elements, so a path with
  spaces is split into separate args (symptom: "0 files scanned"). Pass ONE argument string
  with each path explicitly quoted: `"--cli --report `"$rep`" `"$path`""`.
- The exe attaches to the console via ConsoleBootstrap; capture with `-RedirectStandardOutput`.
- A non-zero exit code (e.g. `--fail-on` gate firing) makes the PowerShell tool report "Exit
  code 1" — that is the intended gate behavior, not a script failure.

## Still pending: i18n migration
- Most UI strings are still Turkish in code (against the English-everywhere principle). The
  localization SYSTEM is built (Strings + LocManager + lang.en.xml + switcher), the main screen is
  migrated; the rest is queued ("finish string migration"). New strings stay Turkish for a
  consistent UI until that sweep; they all migrate together.

## Continuous-loop discipline (the big one)
- `ScheduleWakeup` ENDS the turn and resumes after a delay → it inherently creates a gap (min 60s,
  it suggested 1200–1800s). NEVER use it to drive a "keep working" loop — that is what produced
  the hated 25-minute dead gaps. Keep working continuously in one turn; do not deliberately stop or
  "wrap up an iteration". The only sanctioned pause-and-resume is a recurring CRON (fires only when
  the REPL is idle, i.e. when you actually stopped) — "if still working ignore, if stopped continue".
- A 5-minute recurring cron (`*/5 * * * *`) is the safety net for this loop. State lives on DISK
  (commits, Brainstorm queue, PROGRESS.md) so a cold cron-resume reads where things stand.

## Invisible reCAPTCHA false-trigger (keyless GUI)
- VT's GUI page uses INVISIBLE reCAPTCHA, so it loads recaptcha / api2/anchor / bframe resources and
  a 0-sized anchor iframe on EVERY clean lookup. Treating those as "a challenge is shown" pops the
  hidden browser to the foreground with no captcha. Only act on a real block: a 429/403 on the
  `/ui/files/<hash>` data call, or a DOM check for a VISIBLE bframe (getBoundingClientRect > 100px).

## In-scan content dedup pattern
- A per-run `ConcurrentDictionary<md5, SemaphoreSlim>` gate around the lookup makes duplicate files
  in one scan share a single VT/GUI lookup: first item looks up + caches, the rest wait on the gate
  then hit the cache. Extract the lookup chain into a method (`DoLookupAsync`) so the gate wraps a
  clean call, not a 40-line block.

## principle 43 "AsyncWait" = built-in Task.WaitAsync
- There is no `AsyncWait` method; .NET 6+ ships `Task.WaitAsync(ct)` / `WaitAsync(TimeSpan)` which
  IS the principle-43 guarantee (cancellation/timeout wins on time even if the inner task ignores
  its token). Use `op.WaitAsync(ct)`, don't hand-roll it.

## Local tool: copy-finding by size
- `es file: size:<bytes>` (Everything CLI) lists same-size FILES across all drives in ms; hash only
  those and keep exact sha256 matches. `file:` excludes folders (Everything indexes folder "size" too).

## WinForms overlay z-order: two Dock.Fill siblings race (see docs/winforms-overlay-zorder.md)
- Adding an overlay Panel `Dock=Fill` + `BringToFront()` over a grid that is ALSO `Dock=Fill` does NOT
  reliably render on top — `--snapshot` showed the overlay behind the grid even after BringToFront and an
  `OnHandleCreated` re-assert. Fix: don't overlay, SWAP — only one `Dock=Fill` control `Visible` at a time
  (`_grid.Visible = !empty; _card.Visible = empty;`). No z-order race possible. The critic-snapshot caught it.

## BindingList<T>.ListChanged fires on item PROPERTY changes too
- It fires for `ItemChanged` whenever a contained item raises `PropertyChanged` (e.g. every per-file verdict
  update during a scan — thousands). To react only to structural changes (add/clear), filter:
  `if (e.ListChangedType is ItemAdded or ItemDeleted or Reset)`. Otherwise a cheap handler runs per row.

## DataGridViewComboBoxColumn bound to an enum
- Bind with `DataPropertyName = nameof(X.EnumProp)` + `DataSource = Enum.GetValues<TEnum>()`. A DataError
  ("value is not valid") fires if a row's value isn't in the DataSource — so make the enum's DEFAULT member
  (value 0) a real, listed value (here `ToastOnly = 0`), and new rows default to it. After `StyleGrid` (which
  sets ReadOnly=true) re-enable editing: `grid.ReadOnly = false`.

## Cross-volume File.Move is a non-atomic copy+delete (see docs/quarantine-move-safety.md)
- `File.Move` across volumes silently degrades to copy-then-delete; a disk-full / USB-yank mid-copy leaves a
  half target or a deleted-but-uncopied source. For sensitive moves (quarantine), preflight free space, and
  when `GetPathRoot(src) != GetPathRoot(dst)` do an explicit `File.Copy` then `File.Delete`, cleaning the
  half target and keeping the source if the copy throws. Same-volume keeps the atomic rename.

## Real-time process-start guard via WMI (see docs/wmi-process-start-guard.md)
- `Win32_ProcessStartTrace` (ManagementEventWatcher, `System.Management` NuGet) needs admin. Off by default;
  degrade gracefully — if `!AdminHelper.IsRunningAsAdmin()` log + don't start, never throw. The image path of
  the new PID comes from `Process.GetProcessById(pid).MainModule?.FileName` (wrap in try; short-lived/protected
  processes deny access). `System.Management` 9.0.0 restores fine on `net10.0-windows`.

## --snapshot only covers some tabs
- The `--snapshot` harness captured tabs 0–3 (Overview/Scan/Quotas/Logs) only — NOT Settings or History. For
  GUI changes on those tabs the critic-snapshot can't see them; rely on a clean build + mirroring a proven
  on-screen pattern (e.g. the verdict-category DataGridView editor) instead.

## Brainstorm orchestration: feed shipped + deferred lists to the proposers (see docs/keyless-vt-brainstorm-orchestration.md)
- A proposer/critic Workflow re-proposes already-shipped or deferred ideas unless you pass the SHIPPED feature
  list AND an explicit "ASLA ÖNERME (deferred): …" block in the prompt. Even so a duplicate slips through —
  verify against the codebase before building and move true duplicates to `Brainstorm/Rejected` with a reason.
- The `Workflow` tool always runs in the background; there is no `run_in_background` param (passing it errors).
- A workflow hit the session token limit mid-run (0/10 kept); after the quota reset, re-invoking with the same
  `scriptPath` (no resume needed since nothing cached) re-ran it cleanly.

## Autonomous loop: implicit questions are still questions (see docs/autonomous-loop-discipline.md)
- The single worst loop failure: ending a turn with a plain-prose "devam dersen build ederim, yoksa
  bekliyorum" — no tool call, but functionally identical to asking (I stopped, deferred to the user). The ban
  is on the FUNCTION not the tool. Also forbidden: treating a status summary as a stop while the queue has
  work, and treating "did a lot / context full" as a reason to pause. The cron heartbeat is the ONLY sanctioned
  cross-turn continuation. Verdict band / protection-sensitive logic must stay correct; defer truly
  unverifiable work (live-VT scrape, large-tree streaming) with notes rather than ship it unverified.

## `bildirim` and apostrophes
- The `bildirim` PowerShell command wraps the message in single quotes internally, so an apostrophe in the
  body (`master'a`) breaks parsing. Keep notification titles/bodies ASCII and apostrophe-free.
