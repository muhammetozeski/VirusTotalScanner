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
/// continues. reCAPTCHA is detected three independent ways (HTTP 429/403 on the data call, a
/// recaptcha resource request, and a DOM check) to make detection reliable.
/// Lookup-only: it cannot upload unknown files.
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
                    Text = "VirusTotal — reCAPTCHA",
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
            Text = "  VirusTotal reCAPTCHA istedi. Lütfen aşağıda çözün, sonra sağdaki düğmeye basın.",
            ForeColor = Color.Black,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
        };
        var btn = new Button
        {
            Text = "Çözdüm, devam et",
            Dock = DockStyle.Right,
            Width = 170,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = Color.Black,
        };
        btn.Click += (_, _) => OnSolvedClicked();
        _bar.Controls.Add(lbl);
        _bar.Controls.Add(btn);
    }

    // ---- reCAPTCHA detection (three independent paths) ----

    static async void OnResponse(object? sender, CoreWebView2WebResourceResponseReceivedEventArgs e)
    {
        var pending = _pending;
        if (pending == null) return;
        try
        {
            string fullUri = e.Request.Uri;

            // (1) recaptcha resource request -> a challenge is being shown
            if (fullUri.Contains("recaptcha", StringComparison.OrdinalIgnoreCase) ||
                fullUri.Contains("/api2/anchor", StringComparison.OrdinalIgnoreCase) ||
                fullUri.Contains("/api2/bframe", StringComparison.OrdinalIgnoreCase))
            {
                ShowCaptcha("recaptcha-request");
                return;
            }

            string path = fullUri.Split('?')[0].TrimEnd('/');
            if (!path.EndsWith("/ui/files/" + _targetHash, StringComparison.OrdinalIgnoreCase)) return;

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
            // (3) DOM check for a visible challenge
            string js = "(function(){try{return !!(document.querySelector('iframe[src*=\\\"recaptcha\\\"]')||" +
                        "document.querySelector('.g-recaptcha')||document.querySelector('#recaptcha,#captcha')||" +
                        "(document.title&&/captcha|are you human|robot/i.test(document.title)));}catch(e){return false;}})()";
            string res = await _web.CoreWebView2.ExecuteScriptAsync(js);
            if (res != null && res.Contains("true")) ShowCaptcha("dom");
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
            _timeoutCts?.CancelAfter(TimeSpan.FromMinutes(5)); // give the user time to solve
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
            _timeoutCts?.CancelAfter(TimeSpan.FromSeconds(45));
            Log("User reports reCAPTCHA solved — retrying lookup.", LogLevel.Info);
            _web!.CoreWebView2.Navigate(_currentUrl); // re-fetch with the now-valid session
        }
        catch (Exception ex) { Log("Solve-retry failed: " + ex.Message, LogLevel.Warning); }
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
