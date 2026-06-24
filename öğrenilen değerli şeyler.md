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
