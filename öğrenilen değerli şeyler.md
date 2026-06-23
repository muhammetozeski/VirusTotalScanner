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
