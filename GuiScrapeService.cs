using System.Drawing;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace VirusTotalScanner;

/// <summary>
/// Keyless VirusTotal lookup: drives a hidden WebView2 (real Chromium) to the public GUI page
/// and captures the page's own internal /ui/files/&lt;hash&gt; response — the same data the API
/// returns, with NO API key and NO quota. If VirusTotal demands a reCAPTCHA, the hidden browser
/// is brought to the foreground so the user can solve it, then it hides again and the lookup
/// continues. A reCAPTCHA is only acted on when it actually blocks us: the data call returns
/// 429/403, or a genuinely VISIBLE challenge is in the DOM. (The page uses invisible reCAPTCHA, so
/// the mere loading of recaptcha resources is ignored — otherwise the window would pop up on every
/// clean lookup.) Lookup-only: it cannot upload unknown files.
/// </summary>
internal static class GuiScrapeService
{
    static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };
    static readonly SemaphoreSlim _gate = new(1, 1);

    static Thread? _thread;
    static Form? _form;
    static WebView2? _web;
    static Panel? _bar;
    static TaskCompletionSource<bool>? _initTcs;
    static volatile bool _initFailed;
    static bool _shuttingDown;

    static string _targetHash = "";
    static string _targetSuffix = ""; // "" = the file report; "/comments" = community comments
    static string _currentUrl = "";
    static TaskCompletionSource<string?>? _pending;
    static CancellationTokenSource? _timeoutCts;
    static volatile bool _captchaShown;

    public static bool IsRuntimeAvailable
    {
        get { try { return !string.IsNullOrEmpty(CoreWebView2Environment.GetAvailableBrowserVersionString()); } catch { return false; } }
    }

    /// <summary>Looks up a hash (sha256 preferred) via the GUI. Returns null if not found / cancelled / timed out.</summary>
    public static async Task<VtFileReport?> LookupAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        await _gate.WaitAsync(ct);
        try
        {
            if (!await EnsureReadyAsync()) return null;

            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _targetHash = hash;
            _currentUrl = "https://www.virustotal.com/gui/file/" + hash;
            _pending = tcs;
            _captchaShown = false;

            Log("Keyless GUI lookup: " + hash, LogLevel.Info);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _timeoutCts = timeout;
            timeout.CancelAfter(TimeSpan.FromSeconds(45)); // extended automatically while a captcha is up

            _form!.BeginInvoke(() =>
            {
                try { _web!.CoreWebView2.Navigate(_currentUrl); }
                catch (Exception ex) { tcs.TrySetResult(null); Log("GUI navigate failed: " + ex.Message, LogLevel.Warning); }
            });

            string? json;
            using (timeout.Token.Register(() => tcs.TrySetResult(null)))
                json = await tcs.Task;

            _pending = null;
            _timeoutCts = null;
            HideBrowser();

            if (string.IsNullOrEmpty(json)) return null;

            var dto = JsonSerializer.Deserialize<VtResponse<VtFileData>>(json, JsonOpts);
            var report = VtApiClient.MapReport(dto?.Data?.Attributes);
            if (report != null) report.Sha256 ??= hash;
            return report;
        }
        catch (Exception ex) { Log("Keyless GUI lookup failed: " + ex.Message, LogLevel.Warning); return null; }
        finally { _gate.Release(); }
    }

    /// <summary>Fetches the community comments for a hash via the GUI (keyless). Empty on miss.</summary>
    public static async Task<List<VtComment>> FetchCommentsAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        var result = new List<VtComment>();
        await _gate.WaitAsync(ct);
        try
        {
            if (!await EnsureReadyAsync()) return result;

            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _targetHash = hash;
            _targetSuffix = "/comments";
            _currentUrl = "https://www.virustotal.com/gui/file/" + hash + "/community";
            _pending = tcs;
            _captchaShown = false;

            Log("Keyless GUI comments: " + hash, LogLevel.Info);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _timeoutCts = timeout;
            timeout.CancelAfter(TimeSpan.FromSeconds(45));

            _form!.BeginInvoke(() =>
            {
                try { _web!.CoreWebView2.Navigate(_currentUrl); }
                catch (Exception ex) { tcs.TrySetResult(null); Log("GUI navigate (comments) failed: " + ex.Message, LogLevel.Warning); }
            });

            string? json;
            using (timeout.Token.Register(() => tcs.TrySetResult(null)))
                json = await tcs.Task;

            _pending = null;
            _timeoutCts = null;
            HideBrowser();

            if (string.IsNullOrEmpty(json)) return result;

            var dto = JsonSerializer.Deserialize<VtResponse<List<VtCommentData>>>(json, JsonOpts);
            foreach (var c in dto?.Data ?? [])
            {
                var a = c.Attributes;
                if (a == null || string.IsNullOrWhiteSpace(a.Text)) continue;
                result.Add(new VtComment
                {
                    Date = a.Date > 0 ? DateTimeOffset.FromUnixTimeSeconds(a.Date).UtcDateTime : null,
                    Text = a.Text,
                    Tags = a.Tags ?? [],
                });
            }
            return result;
        }
        catch (Exception ex) { Log("Keyless GUI comments failed: " + ex.Message, LogLevel.Warning); return result; }
        finally { _targetSuffix = ""; _gate.Release(); }
    }

    /// <summary>Fetches the aggregated sandbox behaviour summary for a hash via the GUI (keyless).</summary>
    public static async Task<VtBehaviour> FetchBehaviourAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        var b = new VtBehaviour();
        await _gate.WaitAsync(ct);
        try
        {
            if (!await EnsureReadyAsync()) return b;

            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _targetHash = hash;
            _targetSuffix = "/behaviours"; // the per-sandbox reports list (the GUI does not call behaviour_summary)
            _currentUrl = "https://www.virustotal.com/gui/file/" + hash + "/behavior";
            _pending = tcs;
            _captchaShown = false;

            Log("Keyless GUI behaviour: " + hash, LogLevel.Info);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _timeoutCts = timeout;
            timeout.CancelAfter(TimeSpan.FromSeconds(45));

            _form!.BeginInvoke(() =>
            {
                try { _web!.CoreWebView2.Navigate(_currentUrl); }
                catch (Exception ex) { tcs.TrySetResult(null); Log("GUI navigate (behaviour) failed: " + ex.Message, LogLevel.Warning); }
            });

            string? json;
            using (timeout.Token.Register(() => tcs.TrySetResult(null)))
                json = await tcs.Task;

            _pending = null;
            _timeoutCts = null;
            HideBrowser();

            if (string.IsNullOrEmpty(json)) return b;

            // /behaviours returns a list of per-sandbox reports; merge them all and dedup.
            var reports = JsonSerializer.Deserialize<VtResponse<List<VtBehaviourReportData>>>(json, JsonOpts)?.Data;
            foreach (var dto in (reports ?? []).Select(r => r.Attributes).Where(a => a != null))
            {
                foreach (var d in dto!.DnsLookups ?? []) if (!string.IsNullOrWhiteSpace(d.Hostname)) b.Network.Add("🌐 " + d.Hostname);
                foreach (var ip in dto.IpTraffic ?? []) if (!string.IsNullOrWhiteSpace(ip.DestinationIp)) b.Network.Add("📡 " + ip.DestinationIp);
                foreach (var f in dto.FilesWritten ?? []) if (!string.IsNullOrWhiteSpace(f)) b.FilesWritten.Add(f);
                foreach (var f in dto.FilesDropped ?? []) if (!string.IsNullOrWhiteSpace(f.Path)) b.FilesWritten.Add("⬇ " + f.Path);
                foreach (var r in dto.RegistryKeysSet ?? []) if (!string.IsNullOrWhiteSpace(r.Key)) b.Registry.Add(r.Key);
                foreach (var p in dto.ProcessesCreated ?? []) if (!string.IsNullOrWhiteSpace(p)) b.Processes.Add(p);
                foreach (var m in dto.Mitre ?? []) if (!string.IsNullOrWhiteSpace(m.Id)) b.Mitre.Add($"{m.Id} {m.Description}".Trim());
            }

            b.Network = b.Network.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.FilesWritten = b.FilesWritten.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.Registry = b.Registry.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.Processes = b.Processes.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            b.Mitre = b.Mitre.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            return b;
        }
        catch (Exception ex) { Log("Keyless GUI behaviour failed: " + ex.Message, LogLevel.Warning); return b; }
        finally { _targetSuffix = ""; _gate.Release(); }
    }

    public static void Shutdown()
    {
        _shuttingDown = true;
        try { _form?.BeginInvoke(() => { try { _web?.Dispose(); _form?.Close(); } catch (Exception ex) { Log("WebView2 shutdown: " + ex.Message, LogLevel.Warning); } }); }
        catch (Exception ex) { Log("WebView2 shutdown dispatch: " + ex.Message, LogLevel.Warning); }
    }

    static Task<bool> EnsureReadyAsync()
    {
        if (_initFailed) return Task.FromResult(false);
        if (_initTcs != null) return _initTcs.Task;

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _initTcs = tcs;

        _thread = new Thread(() =>
        {
            try
            {
                ApplicationConfiguration.Initialize();
                _form = new Form
                {
                    Width = 1100,
                    Height = 820,
                    ShowInTaskbar = false,
                    Opacity = 0,
                    FormBorderStyle = FormBorderStyle.None,
                    StartPosition = FormStartPosition.Manual,
                    Location = new Point(-4000, -4000),
                    Text = Strings.CaptchaWindowTitle,
                };
                _form.FormClosing += (_, e) =>
                {
                    if (_shuttingDown) return;
                    e.Cancel = true; // singleton browser — never really close, just hide
                    HideBrowser();
                };

                BuildCaptchaBar();
                _web = new WebView2 { Dock = DockStyle.Fill };
                _form.Controls.Add(_web);
                _form.Controls.Add(_bar);

                _form.Load += async (_, _) =>
                {
                    try
                    {
                        string userData = Path.Combine(ConfigPathResolver.DataFolder, "webview2");
                        Directory.CreateDirectory(userData);
                        var env = await CoreWebView2Environment.CreateAsync(null, userData);
                        await _web.EnsureCoreWebView2Async(env);
                        _web.CoreWebView2.WebResourceResponseReceived += OnResponse;
                        _web.CoreWebView2.NavigationCompleted += OnNavigationCompleted;
                        tcs.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        _initFailed = true;
                        Log("WebView2 init failed: " + ex.Message, LogLevel.Error);
                        tcs.TrySetResult(false);
                    }
                };

                Application.Run(_form);
            }
            catch (Exception ex)
            {
                _initFailed = true;
                Log("WebView2 host thread failed: " + ex.Message, LogLevel.Error);
                tcs.TrySetResult(false);
            }
        })
        { IsBackground = true, Name = "vt-webview" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        return tcs.Task;
    }

    static void BuildCaptchaBar()
    {
        _bar = new Panel { Dock = DockStyle.Top, Height = 46, BackColor = Color.FromArgb(0xE3, 0xB3, 0x41), Visible = false };
        var lbl = new Label
        {
            Text = Strings.CaptchaBarPrompt,
            ForeColor = Color.Black,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
        };
        var btn = new Button
        {
            Text = Strings.CaptchaBtnSolved,
            Dock = DockStyle.Right,
            Width = 170,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = Color.Black,
        };
        btn.Click += (_, _) => OnSolvedClicked();
        var apiBtn = new Button
        {
            Text = Strings.CaptchaBtnSwitchToApi,
            Dock = DockStyle.Right,
            Width = 160,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = Color.Black,
        };
        apiBtn.Click += (_, _) => OnSwitchToApi();
        _bar.Controls.Add(lbl);
        _bar.Controls.Add(btn);
        _bar.Controls.Add(apiBtn);
    }

    // ---- reCAPTCHA detection (three independent paths) ----

    static async void OnResponse(object? sender, CoreWebView2WebResourceResponseReceivedEventArgs e)
    {
        var pending = _pending;
        if (pending == null) return;
        try
        {
            string fullUri = e.Request.Uri;

            // NOTE: the VT page uses INVISIBLE reCAPTCHA, so it loads recaptcha / api2/anchor / bframe
            // resources on every clean lookup for risk scoring. Their mere presence is NOT a challenge,
            // so we do NOT trigger on resource requests — only a blocked data call (429/403) or a
            // genuinely VISIBLE DOM challenge counts. This stops the browser popping up with no captcha.

            string path = fullUri.Split('?')[0].TrimEnd('/');
            if (!path.EndsWith("/ui/files/" + _targetHash + _targetSuffix, StringComparison.OrdinalIgnoreCase)) return;

            int code = e.Response.StatusCode;
            if (code == 200)
            {
                var stream = await e.Response.GetContentAsync();
                if (stream == null) { pending.TrySetResult(null); return; }
                using var r = new StreamReader(stream);
                pending.TrySetResult(await r.ReadToEndAsync());
                return;
            }

            // (2) the data call was blocked -> almost always reCAPTCHA on the keyless path
            if (code is 429 or 403)
            {
                string body = await SafeBody(e.Response);
                if (code == 429 && !body.Contains("recaptcha", StringComparison.OrdinalIgnoreCase) && body.Length > 0)
                {
                    // a non-captcha 429 (rare) — treat as temporarily blocked, not found
                    Log("Keyless GUI 429 without recaptcha for " + _targetHash, LogLevel.Warning);
                }
                ShowCaptcha("http-" + code);
                return;
            }

            // 404 etc. -> genuinely not in VT
            pending.TrySetResult(null);
        }
        catch (Exception ex)
        {
            Log("Keyless GUI response handling failed: " + ex.Message, LogLevel.Warning);
            pending.TrySetResult(null);
        }
    }

    static async void OnNavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        if (_pending == null || _captchaShown || _web == null) return;
        try
        {
            // (3) DOM check for a VISIBLE challenge only. Invisible reCAPTCHA always injects a 0-sized
            // anchor iframe, so we must require the challenge frame (api2/bframe) to be actually shown
            // with real size, or an explicit challenge widget / page title — otherwise we'd false-fire.
            string js = "(function(){try{" +
                        "var f=document.querySelector('iframe[src*=\\\"api2/bframe\\\"]');" +
                        "if(f){var r=f.getBoundingClientRect();if(r.width>100&&r.height>100)return true;}" +
                        "if(document.querySelector('#rc-imageselect,.rc-imageselect,.g-recaptcha-bubble-arrow'))return true;" +
                        "if(document.title&&/are you human|verify you are|complete the captcha/i.test(document.title))return true;" +
                        "return false;}catch(e){return false;}})()";
            string res = await _web.CoreWebView2.ExecuteScriptAsync(js);
            if (res != null && res.Contains("true")) ShowCaptcha("dom-visible");
        }
        catch (Exception ex) { Log("Captcha DOM check failed: " + ex.Message, LogLevel.Warning); }
    }

    static void ShowCaptcha(string via)
    {
        if (_captchaShown || _form == null || _bar == null) return;
        _captchaShown = true;
        Log("reCAPTCHA detected (" + via + ") — bringing browser to foreground.", LogLevel.Warning);

        try
        {
            _timeoutCts?.CancelAfter(Timeout.InfiniteTimeSpan); // no timeout while the user is solving — only the button (or cancel) continues
            _form.BeginInvoke(() =>
            {
                try
                {
                    _bar!.Visible = true;
                    _form.FormBorderStyle = FormBorderStyle.Sizable;
                    _form.ShowInTaskbar = true;
                    _form.Opacity = 1;
                    var screen = Screen.PrimaryScreen!.WorkingArea;
                    _form.Location = new Point(screen.X + (screen.Width - _form.Width) / 2, screen.Y + (screen.Height - _form.Height) / 2);
                    _form.WindowState = FormWindowState.Normal;
                    _form.Show();
                    _form.TopMost = true;
                    _form.Activate();
                    _form.BringToFront();
                    _form.TopMost = false;
                }
                catch (Exception ex) { Log("ShowCaptcha UI failed: " + ex.Message, LogLevel.Warning); }
            });
        }
        catch (Exception ex) { Log("ShowCaptcha failed: " + ex.Message, LogLevel.Warning); }
    }

    static void OnSolvedClicked()
    {
        try
        {
            _bar!.Visible = false;
            _captchaShown = false;
            _timeoutCts?.CancelAfter(TimeSpan.FromSeconds(45)); // safety net for the re-fetch only
            Log("User reports reCAPTCHA solved — retrying lookup.", LogLevel.Info);
            _web!.CoreWebView2.Navigate(_currentUrl); // re-fetch with the now-valid session
        }
        catch (Exception ex) { Log("Solve-retry failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>User chose to use an API key instead of solving the reCAPTCHA — give up the GUI
    /// lookup so the scan falls back to the API path.</summary>
    static void OnSwitchToApi()
    {
        Log("User chose API over reCAPTCHA.", LogLevel.Info);
        _pending?.TrySetResult(null);
        HideBrowser();
    }

    static void HideBrowser()
    {
        if (_form == null) return;
        try
        {
            _form.BeginInvoke(() =>
            {
                try
                {
                    if (_bar != null) _bar.Visible = false;
                    _captchaShown = false;
                    _form.TopMost = false;
                    _form.Opacity = 0;
                    _form.ShowInTaskbar = false;
                    _form.FormBorderStyle = FormBorderStyle.None;
                    _form.WindowState = FormWindowState.Minimized;
                    _form.Location = new Point(-4000, -4000);
                    _form.Hide();
                }
                catch (Exception ex) { Log("HideBrowser UI failed: " + ex.Message, LogLevel.Warning); }
            });
        }
        catch (Exception ex) { Log("HideBrowser failed: " + ex.Message, LogLevel.Warning); }
    }

    static async Task<string> SafeBody(CoreWebView2WebResourceResponseView resp)
    {
        try
        {
            var s = await resp.GetContentAsync();
            if (s == null) return "";
            using var r = new StreamReader(s);
            return await r.ReadToEndAsync();
        }
        catch { return ""; }
    }
}
