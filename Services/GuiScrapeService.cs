using System.Drawing;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace VirusTotalScanner;

/// <summary>
/// Keyless VirusTotal lookup: drives a hidden WebView2 (real Chromium) to the public GUI page
/// and captures the page's own internal /ui/files/&lt;hash&gt; response — the same data the API
/// returns, with NO API key and NO quota. If VirusTotal demands a reCAPTCHA the app first tries the
/// single "I am not a robot" click by itself; only when a picture puzzle actually follows is the
/// hidden browser brought to the foreground for the user. A reCAPTCHA is only acted on when it
/// really blocks us: the data call returns 429/403, or a genuinely VISIBLE challenge is in the DOM.
/// (The page uses invisible reCAPTCHA, so the mere loading of recaptcha resources is ignored.)
///
/// The public UI is rate-limited per SOURCE IP, so the browser can be pointed at
/// <see cref="TorService"/>'s SOCKS proxy; changing the proxy (or the circuit) rebuilds the browser
/// with a clean profile, because VirusTotal ties its session cookie to the address that got it.
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
    static Button? _torBtn;
    static Label? _barLabel;
    static TaskCompletionSource<bool>? _initTcs;
    static volatile bool _initFailed;
    static volatile bool _shuttingDown;
    static volatile bool _restartRequested;
    static string? _activeProxy;                  // the proxy the live browser was created with

    static string _targetHash = "";
    static string _targetSuffix = ""; // "" = the file report; "/comments" = community comments
    static string _currentUrl = "";
    static TaskCompletionSource<string?>? _pending;
    static TaskCompletionSource<bool>? _navDone;
    static CancellationTokenSource? _timeoutCts;
    static volatile bool _captchaShown;
    static volatile bool _autoSolving;
    static volatile bool _autoSolveTried;
    static volatile bool _blockReported; // one IP-block strike per lookup, not per retry
    static volatile bool _challengeSeen; // this lookup ran into a challenge, whether or not it was shown

    /// <summary>How long a human is given to answer a challenge the app could not click through before
    /// the lookup gives up. It used to be forever, which is fine at a desk and fatal overnight: the
    /// single browser is behind one gate, so one unanswered challenge froze every keyless lookup in the
    /// whole scan. If somebody is there they still have two minutes; if not, the scan carries on.</summary>
    static readonly TimeSpan CaptchaSolveWindow = TimeSpan.FromMinutes(2);

    /// <summary>How long one lookup may take. The VirusTotal page is a single-page app that fetches its
    /// own data over several round trips, and every one of them goes through three relays when Tor is
    /// carrying the traffic. A route probe showed the first Tor lookup timing out at 45 s without ever
    /// being challenged — the page simply had not finished. Direct stays at 45 s.</summary>
    static TimeSpan FetchTimeout => TorService.IsActive ? TimeSpan.FromSeconds(150) : TimeSpan.FromSeconds(45);

    /// <summary>After an unanswered challenge the channel is parked for a while. Without this every
    /// remaining file would pay the same two minutes to learn the same thing.</summary>
    static readonly TimeSpan BlockedCooldown = TimeSpan.FromMinutes(3);
    static long _blockedUntilTicks;      // DateTime.UtcNow.Ticks; 0 = open. Interlocked-accessed.
    static long _lastBlockedLogTicks;

    /// <summary>True while the keyless channel is parked after an unanswered challenge.</summary>
    public static bool IsBlocked => Interlocked.Read(ref _blockedUntilTicks) > DateTime.UtcNow.Ticks;

    /// <summary>When the channel reopens, or null when it is open now.</summary>
    public static DateTime? BlockedUntilUtc
    {
        get { long t = Interlocked.Read(ref _blockedUntilTicks); return t > DateTime.UtcNow.Ticks ? new DateTime(t, DateTimeKind.Utc) : null; }
    }

    static void ParkChannel(string why)
    {
        Interlocked.Exchange(ref _blockedUntilTicks, DateTime.UtcNow.Add(BlockedCooldown).Ticks);
        Log($"Keyless channel parked for {BlockedCooldown.TotalMinutes:F0} min ({why}). Lookups fall through to the API meanwhile.", LogLevel.Warning);
        UiStatusHub.Report(Strings.StatusSourceScan, string.Format(Strings.KeylessParkedFormat, (int)BlockedCooldown.TotalMinutes), StatusSeverity.Warning);
    }

    static void OpenChannel(string why)
    {
        if (Interlocked.Exchange(ref _blockedUntilTicks, 0) == 0) return;
        Log("Keyless channel reopened: " + why, LogLevel.Info);
    }
    static readonly List<CoreWebView2Frame> _frames = [];

    public static bool IsRuntimeAvailable
    {
        get { try { return !string.IsNullOrEmpty(CoreWebView2Environment.GetAvailableBrowserVersionString()); } catch { return false; } }
    }

    /// <summary>How the most recent keyless lookup ended. Diagnostic only — the scan path just looks at
    /// the returned report — but it is what lets the network probe say WHY an exit address failed
    /// instead of only that it did.</summary>
    public static KeylessOutcome LastOutcome { get; private set; } = KeylessOutcome.None;

    /// <summary>Probe mode: never bring the window up and never try the checkbox — a challenge is
    /// reported as a challenge and the lookup ends. Used by the network probe to measure how an exit
    /// address is actually treated, with no human and no automation in the way.</summary>
    public static bool ProbeMode { get; set; }

    /// <summary>Drop the current browser (profile + cookies included) before the next lookup. Called
    /// when Tor is switched on/off or the circuit changes: the old VirusTotal session cookie belongs
    /// to the old exit address and would carry the old block straight over to the new one.</summary>
    public static void InvalidateSession(string why)
    {
        _restartRequested = true;
        // A new route/profile is exactly the thing a parked channel was waiting for.
        OpenChannel("session invalidated: " + why);
        Log("Keyless browser session invalidated: " + why, LogLevel.Info);
    }

    /// <summary>The one navigate-and-capture round trip all three fetches share: opens the GUI page,
    /// waits for the page's own /ui/files/&lt;hash&gt;&lt;suffix&gt; response (captcha flow included)
    /// and returns the captured JSON, or null on miss / timeout / cancel / browser busy. Serialized by
    /// the gate: only one lookup can drive the single browser at a time, so a caller that has another
    /// option passes a short <paramref name="maxQueueWait"/> and takes null as "busy, use the API".</summary>
    static async Task<string?> FetchJsonAsync(string hash, string suffix, string pageUrl, string logLabel, CancellationToken ct, TimeSpan maxQueueWait)
    {
        LastOutcome = KeylessOutcome.None;
        if (IsBlocked)
        {
            LastOutcome = KeylessOutcome.Parked;
            // Rate-limit the log line: during a big scan this is hit once per file.
            long last = Interlocked.Read(ref _lastBlockedLogTicks);
            if (DateTime.UtcNow.Ticks - last > TimeSpan.FromSeconds(30).Ticks)
            {
                Interlocked.Exchange(ref _lastBlockedLogTicks, DateTime.UtcNow.Ticks);
                Log($"Keyless lookup skipped: channel parked until {BlockedUntilUtc:HH:mm:ss} UTC.", LogLevel.Info);
            }
            return null;
        }
        if (!await _gate.WaitAsync(maxQueueWait, ct)) { LastOutcome = KeylessOutcome.Busy; return null; }
        try
        {
            if (!await EnsureReadyAsync()) { LastOutcome = KeylessOutcome.NoRuntime; return null; }

            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _targetHash = hash;
            _targetSuffix = suffix;
            _currentUrl = pageUrl;
            _pending = tcs;
            _captchaShown = false;
            _autoSolveTried = false;
            _autoSolving = false;
            _blockReported = false;
            _challengeSeen = false;

            Log(logLabel + ": " + hash, LogLevel.Info);
            using var op = OpLog.Begin("Keyless lookup", $"{hash[..Math.Min(16, hash.Length)]}… route={(_activeProxy ?? "direct")} url={pageUrl}");

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            _timeoutCts = timeout;
            timeout.CancelAfter(FetchTimeout); // extended automatically while a captcha is up
            op.Step($"timeout {FetchTimeout.TotalSeconds:F0}s");

            Navigate(_currentUrl, logLabel, tcs);

            string? json;
            using (timeout.Token.Register(() => tcs.TrySetResult(null)))
                json = await tcs.Task;

            bool gaveUpOnChallenge = (_captchaShown || _challengeSeen) && string.IsNullOrEmpty(json);
            LastOutcome = !string.IsNullOrEmpty(json) ? KeylessOutcome.Report
                        : gaveUpOnChallenge ? KeylessOutcome.Challenged
                        : timeout.IsCancellationRequested ? KeylessOutcome.TimedOut
                        : KeylessOutcome.NotFound;
            op.Ok($"{LastOutcome}" + (json != null ? $", {json.Length} chars" : ""));
            _pending = null;
            _timeoutCts = null;
            HideBrowser();
            if (gaveUpOnChallenge && !ProbeMode) ParkChannel("a challenge went unanswered");
            else if (!string.IsNullOrEmpty(json)) OpenChannel("a lookup succeeded");
            return string.IsNullOrEmpty(json) ? null : json;
        }
        finally { _targetSuffix = ""; _gate.Release(); }
    }

    static void Navigate(string url, string logLabel, TaskCompletionSource<string?>? failTo)
    {
        try
        {
            _navDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _form!.BeginInvoke(() =>
            {
                try { _web!.CoreWebView2.Navigate(url); }
                catch (Exception ex)
                {
                    failTo?.TrySetResult(null);
                    _navDone?.TrySetResult(false);
                    Log(logLabel + " navigate failed: " + ex.Message, LogLevel.Warning);
                }
            });
        }
        catch (Exception ex)
        {
            failTo?.TrySetResult(null);
            _navDone?.TrySetResult(false);
            Log(logLabel + " navigate dispatch failed: " + ex.Message, LogLevel.Warning);
        }
    }

    /// <summary>Looks up a hash (sha256 preferred) via the GUI. Returns null if not found / cancelled /
    /// timed out / the browser was busy and the caller was not willing to wait for it.</summary>
    public static async Task<VtFileReport?> LookupAsync(string hash, CancellationToken ct = default, TimeSpan? maxQueueWait = null)
    {
        hash = hash.Trim().ToLowerInvariant();
        try
        {
            string? json = await FetchJsonAsync(hash, "", AppConstants.VtGuiFile + hash, "Keyless GUI lookup", ct,
                maxQueueWait ?? Timeout.InfiniteTimeSpan);
            if (json == null) return null;

            var dto = JsonSerializer.Deserialize<VtResponse<VtFileData>>(json, JsonOpts);
            var report = VtApiClient.MapReport(dto?.Data?.Attributes);
            if (report != null) report.Sha256 ??= hash;
            return report;
        }
        catch (Exception ex) { Log("Keyless GUI lookup failed: " + ex.Message, LogLevel.Warning); return null; }
    }

    /// <summary>Fetches the community comments for a hash via the GUI (keyless). Empty on miss.</summary>
    public static async Task<List<VtComment>> FetchCommentsAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        var result = new List<VtComment>();
        try
        {
            string? json = await FetchJsonAsync(hash, "/comments", AppConstants.VtGuiFile + hash + "/community", "Keyless GUI comments", ct, Timeout.InfiniteTimeSpan);
            if (json == null) return result;

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
    }

    /// <summary>Fetches the aggregated sandbox behaviour summary for a hash via the GUI (keyless).</summary>
    public static async Task<VtBehaviour> FetchBehaviourAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        var b = new VtBehaviour();
        try
        {
            // "/behaviours" is the per-sandbox reports list (the GUI does not call behaviour_summary).
            string? json = await FetchJsonAsync(hash, "/behaviours", AppConstants.VtGuiFile + hash + "/behavior", "Keyless GUI behaviour", ct, Timeout.InfiniteTimeSpan);
            if (json == null) return b;

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
    }

    public static void Shutdown()
    {
        _shuttingDown = true;
        try { _form?.BeginInvoke(() => { try { _web?.Dispose(); _form?.Close(); } catch (Exception ex) { Log("WebView2 shutdown: " + ex.Message, LogLevel.Warning); } }); }
        catch (Exception ex) { Log("WebView2 shutdown dispatch: " + ex.Message, LogLevel.Warning); }
    }

    // ---- browser lifecycle ----

    static async Task<bool> EnsureReadyAsync()
    {
        string? wantProxy = TorService.ProxyUrl;
        using var op = OpLog.Begin("Keyless browser ready-check",
            $"proxy now='{_activeProxy ?? "direct"}' wanted='{wantProxy ?? "direct"}' restartRequested={_restartRequested} started={_initTcs != null}");

        if (_initTcs != null && (_restartRequested || _activeProxy != wantProxy))
        {
            Log($"Rebuilding the keyless browser (proxy '{_activeProxy ?? "direct"}' -> '{wantProxy ?? "direct"}').", LogLevel.Info);
            op.Step("tearing the old browser down");
            TearDown();
        }

        if (_initFailed) { op.Fail("WebView2 init had already failed"); return false; }
        if (_initTcs != null)
        {
            op.Step("waiting for an in-flight start");
            bool alive = await _initTcs.Task;
            if (alive) op.Ok("reused"); else op.Fail("the in-flight start failed");
            return alive;
        }

        op.Step("starting a browser");
        bool ok = await StartBrowserAsync(wantProxy);
        if (ok) op.Ok("started"); else op.Fail("start failed");
        return ok;
    }

    static void TearDown()
    {
        using var op = OpLog.Begin("Keyless browser teardown", $"thread={_thread?.ManagedThreadId.ToString() ?? "-"}");
        var form = _form;
        var thread = _thread;
        _shuttingDown = true;
        try
        {
            form?.BeginInvoke(() =>
            {
                try { _web?.Dispose(); } catch (Exception ex) { Log("WebView dispose failed: " + ex.Message, LogLevel.Warning); }
                try { form.Close(); } catch (Exception ex) { Log("Browser form close failed: " + ex.Message, LogLevel.Warning); }
            });
            op.Step("close dispatched to the browser thread");
        }
        catch (Exception ex) { Log("Browser teardown dispatch failed: " + ex.Message, LogLevel.Warning); op.Step("dispatch failed: " + ex.Message); }

        bool joined = false;
        try { joined = thread?.Join(TimeSpan.FromSeconds(8)) ?? true; }
        catch (Exception ex) { Log("Browser thread join failed: " + ex.Message, LogLevel.Warning); op.Step("join failed: " + ex.Message); }
        finally
        {
            lock (_frames) _frames.Clear();
            _form = null; _web = null; _bar = null; _torBtn = null; _barLabel = null;
            _thread = null; _initTcs = null; _initFailed = false;
            _shuttingDown = false; _restartRequested = false;
            if (joined) op.Ok("thread ended"); else op.Fail("the browser thread did not end within 8 s; state reset anyway");
        }
    }

    static Task<bool> StartBrowserAsync(string? proxyUrl)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _initTcs = tcs;
        _activeProxy = proxyUrl;

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
                        // A separate profile per route: a VirusTotal session cookie earned on the direct
                        // address is worthless (and suspicious) on a Tor exit, and vice versa.
                        string userData = Path.Combine(ConfigPathResolver.DataFolder,
                            proxyUrl == null ? "webview2" : "webview2-tor");
                        Directory.CreateDirectory(userData);

                        CoreWebView2Environment env;
                        try
                        {
                            var opts = new CoreWebView2EnvironmentOptions();
                            if (proxyUrl != null)
                            {
                                // Just the proxy. An earlier attempt also passed
                                // --proxy-bypass-list="<-loopback>" to stop Chromium bypassing the proxy
                                // for loopback; that also pushes WebView2's own internal loopback traffic
                                // at the SOCKS port, and every lookup then timed out with no response at
                                // all — not even a 429.
                                opts.AdditionalBrowserArguments = $"--proxy-server=\"{proxyUrl}\"";
                                Log("WebView2 browser arguments: " + opts.AdditionalBrowserArguments, LogLevel.Info);
                            }
                            env = await CoreWebView2Environment.CreateAsync(null, userData, opts);
                        }
                        catch (Exception exOpts)
                        {
                            // Never lose the keyless engine over a proxy-argument problem: fall back to a
                            // plain environment and say so, rather than disabling the whole path.
                            Log("WebView2 environment with proxy failed, retrying direct: " + exOpts.Message, LogLevel.Warning);
                            _activeProxy = null;
                            env = await CoreWebView2Environment.CreateAsync(null, Path.Combine(ConfigPathResolver.DataFolder, "webview2"));
                        }

                        await _web.EnsureCoreWebView2Async(env);
                        _web.CoreWebView2.WebResourceResponseReceived += OnResponse;
                        _web.CoreWebView2.NavigationCompleted += OnNavigationCompleted;
                        _web.CoreWebView2.FrameCreated += OnFrameCreated;
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

    static void OnFrameCreated(object? sender, CoreWebView2FrameCreatedEventArgs e)
    {
        try
        {
            var frame = e.Frame;
            lock (_frames) _frames.Add(frame);
            frame.Destroyed += (s, _) => { lock (_frames) _frames.Remove((CoreWebView2Frame)s!); };
        }
        catch (Exception ex) { Log("Frame tracking failed: " + ex.Message, LogLevel.Warning); }
    }

    static void BuildCaptchaBar()
    {
        _bar = new Panel { Dock = DockStyle.Top, Height = 46, BackColor = Color.FromArgb(0xE3, 0xB3, 0x41), Visible = false };
        _barLabel = new Label
        {
            Text = Strings.CaptchaBarPrompt,
            ForeColor = Color.Black,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
        };
        var btn = MakeBarButton(Strings.CaptchaBtnSolved, 170);
        btn.Click += (_, _) => OnSolvedClicked();
        var apiBtn = MakeBarButton(Strings.CaptchaBtnSwitchToApi, 160);
        apiBtn.Click += (_, _) => OnSwitchToApi();
        _torBtn = MakeBarButton(Strings.CaptchaBtnUseTor, 190);
        _torBtn.Click += (_, _) => OnTorButtonClicked();

        _bar.Controls.Add(_barLabel);
        _bar.Controls.Add(btn);
        _bar.Controls.Add(apiBtn);
        _bar.Controls.Add(_torBtn);
    }

    static Button MakeBarButton(string text, int width) => new()
    {
        Text = text,
        Dock = DockStyle.Right,
        Width = width,
        FlatStyle = FlatStyle.Flat,
        BackColor = Color.White,
        ForeColor = Color.Black,
    };

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
            Log($"Keyless <- HTTP {code} {e.Response.ReasonPhrase} for {path}", LogLevel.Info);
            if (code == 200)
            {
                var stream = await e.Response.GetContentAsync();
                if (stream == null)
                {
                    // WebView2 hands the body over for a limited time; a miss here is not "not found".
                    Log("Keyless: HTTP 200 but the body was no longer readable.", LogLevel.Warning);
                    pending.TrySetResult(null);
                    return;
                }
                using var r = new StreamReader(stream);
                string body = await r.ReadToEndAsync();
                Log($"Keyless <- body {body.Length} chars for {_targetHash}", LogLevel.Debug);
                pending.TrySetResult(body);
                return;
            }

            // (2) the data call was blocked -> reCAPTCHA, or this source IP is out of public-UI budget
            if (code is 429 or 403)
            {
                string body = await SafeBody(e.Response);
                bool captcha = body.Contains("captcha", StringComparison.OrdinalIgnoreCase);
                // Whether VirusTotal words it as a reCAPTCHA demand or a bare 429, this is the SOURCE IP
                // being told it has asked enough; a fresh exit address is the only thing that lifts it.
                // Counted once per lookup, not once per retry, so one blocked file is one strike.
                if (!_blockReported)
                {
                    _blockReported = true;
                    NetworkBlockMonitor.ReportIpBlocked($"keyless-http-{code}" + (captcha ? "-recaptcha" : ""));
                }
                if (!captcha)
                    Log($"Keyless GUI {code} without a captcha marker for {_targetHash} — source IP is blocked.", LogLevel.Warning);
                HandleCaptcha("http-" + code);
                return;
            }

            // 404 etc. -> genuinely not in VT
            Log($"Keyless: HTTP {code} treated as 'VirusTotal does not have {_targetHash}'.", LogLevel.Debug);
            pending.TrySetResult(null);
        }
        catch (Exception ex)
        {
            Log($"Keyless GUI response handling failed for {_targetHash}: {ex.Message}", LogLevel.Warning);
            pending.TrySetResult(null);
        }
    }

    static async void OnNavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        // The only place a proxy/DNS/TLS failure is visible: without this, a route that cannot load the
        // page at all looks exactly like a slow one — both just time out with nothing logged.
        Log($"Keyless navigation completed: success={e.IsSuccess} status={e.WebErrorStatus} httpStatus={e.HttpStatusCode}", LogLevel.Info);
        _navDone?.TrySetResult(e.IsSuccess);
        if (_pending == null || _captchaShown || _autoSolving || _web == null) return;
        try
        {
            if (await HasVisibleChallengeAsync()) HandleCaptcha("dom-visible");
        }
        catch (Exception ex) { Log("Captcha DOM check failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>(3) DOM check for a VISIBLE challenge only. Invisible reCAPTCHA always injects a 0-sized
    /// anchor iframe, so the challenge frame (api2/bframe) must be actually shown with real size, or an
    /// explicit challenge widget / page title must be present — otherwise we'd false-fire.</summary>
    static async Task<bool> HasVisibleChallengeAsync()
    {
        if (_web == null) return false;
        const string js = "(function(){try{" +
                          "var f=document.querySelector('iframe[src*=\\\"api2/bframe\\\"]');" +
                          "if(f){var r=f.getBoundingClientRect();if(r.width>100&&r.height>100)return true;}" +
                          "if(document.querySelector('#rc-imageselect,.rc-imageselect,.g-recaptcha-bubble-arrow'))return true;" +
                          "if(document.title&&/are you human|verify you are|complete the captcha/i.test(document.title))return true;" +
                          "return false;}catch(e){return false;}})()";
        string res = await RunOnUiAsync(() => _web!.CoreWebView2.ExecuteScriptAsync(js));
        return res != null && res.Contains("true");
    }

    // ---- captcha handling: try the one click ourselves before disturbing the user ----

    static void HandleCaptcha(string via)
    {
        if (_captchaShown || _autoSolving) return;
        _challengeSeen = true;
        if (ProbeMode)
        {
            // Measuring, not scanning: report the challenge and end the lookup. No window, no clicking —
            // the whole point is to see how this exit address is treated on its own.
            Log("Probe: challenge on this route (" + via + ").", LogLevel.Info);
            _pending?.TrySetResult(null);
            return;
        }
        if (!Settings.CaptchaAutoClick || _autoSolveTried) { ShowCaptcha(via); return; }
        _autoSolveTried = true;
        _autoSolving = true;
        _timeoutCts?.CancelAfter(Timeout.InfiniteTimeSpan); // don't time out mid-attempt

        _ = Task.Run(async () =>
        {
            bool solved = false;
            try { solved = await TryAutoSolveAsync(); }
            catch (Exception ex) { Log("Automatic captcha click failed: " + ex.Message, LogLevel.Warning); }
            finally
            {
                _autoSolving = false;
                if (solved)
                {
                    Log("reCAPTCHA passed with the single click — the user was not interrupted.", LogLevel.Info);
                    _timeoutCts?.CancelAfter(FetchTimeout);
                }
                else if (_pending is { Task.IsCompleted: false })
                {
                    ShowCaptcha(via + "+autoclick-failed");
                }
            }
        });
    }

    /// <summary>Loads the page, clicks the reCAPTCHA checkbox inside its own frame and waits to see
    /// whether that alone satisfied it. Returns true when the checkbox went green with no picture
    /// puzzle and the page was re-requested; false when a puzzle appeared or nothing worked.</summary>
    static async Task<bool> TryAutoSolveAsync()
    {
        var pending = _pending;
        if (pending == null || _web == null) return false;

        // A 429 on the XHR does not necessarily paint the widget — reload so the checkbox exists.
        Navigate(_currentUrl, "Captcha auto-click reload", null);
        var nav = _navDone;
        if (nav != null)
        {
            var done = await Task.WhenAny(nav.Task, Task.Delay(TimeSpan.FromSeconds(20)));
            if (done != nav.Task) { Log("Captcha auto-click: the page did not finish loading.", LogLevel.Warning); return false; }
        }
        if (pending.Task.IsCompleted) return true; // the reload alone was enough

        var deadline = DateTime.UtcNow.AddSeconds(20);
        bool clicked = false;
        while (DateTime.UtcNow < deadline)
        {
            if (pending.Task.IsCompleted) return true;

            string state = await ClickAnchorInFramesAsync();
            if (state == "already" || state == "checked") { clicked = true; break; }
            if (state == "clicked") clicked = true;

            if (clicked && await HasVisibleChallengeAsync())
            {
                Log("reCAPTCHA answered the click with a picture puzzle — handing it to the user.", LogLevel.Info);
                return false;
            }
            await Task.Delay(600);
        }

        if (!clicked) { Log("Captcha auto-click: the checkbox was never reachable.", LogLevel.Warning); return false; }
        if (await HasVisibleChallengeAsync()) return false;
        if (pending.Task.IsCompleted) return true;

        // Checkbox accepted with no puzzle: re-issue the data call with the now-valid token.
        Navigate(_currentUrl, "Captcha auto-click retry", null);
        var finish = await Task.WhenAny(pending.Task, Task.Delay(TimeSpan.FromSeconds(25)));
        return finish == pending.Task && pending.Task.Result != null;
    }

    /// <summary>Runs the checkbox click inside every child frame; only the reCAPTCHA anchor frame
    /// matches, which is why the script checks its own location first. Returns the frame's answer:
    /// "clicked", "checked", "already", or "none".</summary>
    static async Task<string> ClickAnchorInFramesAsync()
    {
        const string js = "(function(){try{" +
                          "if(location.href.indexOf('api2/anchor')<0)return 'skip';" +
                          "var c=document.getElementById('recaptcha-anchor');" +
                          "if(!c)return 'nochk';" +
                          "if(c.getAttribute('aria-checked')==='true')return 'already';" +
                          "c.click();" +
                          "return c.getAttribute('aria-checked')==='true'?'checked':'clicked';" +
                          "}catch(e){return 'err';}})()";

        List<CoreWebView2Frame> frames;
        lock (_frames) frames = [.. _frames];
        string best = "none";
        foreach (var frame in frames)
        {
            try
            {
                string raw = await RunOnUiAsync(() => frame.ExecuteScriptAsync(js));
                string val = (raw ?? "").Trim('"');
                if (val is "already" or "checked") return val;
                if (val == "clicked") best = "clicked";
            }
            catch (Exception ex) { Log("Frame click attempt failed: " + ex.Message, LogLevel.Warning); }
        }
        return best;
    }

    /// <summary>Marshals a WebView2 call onto the browser's own UI thread and awaits its result.</summary>
    static Task<string> RunOnUiAsync(Func<Task<string>> action)
    {
        var form = _form;
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (form == null || !form.IsHandleCreated) { tcs.TrySetResult(""); return tcs.Task; }
        try
        {
            form.BeginInvoke(async () =>
            {
                try { tcs.TrySetResult(await action() ?? ""); }
                catch (Exception ex) { Log("Browser script call failed: " + ex.Message, LogLevel.Warning); tcs.TrySetResult(""); }
            });
        }
        catch (Exception ex) { Log("Browser script dispatch failed: " + ex.Message, LogLevel.Warning); tcs.TrySetResult(""); }
        return tcs.Task;
    }

    static void ShowCaptcha(string via)
    {
        if (_captchaShown || _form == null || _bar == null) return;
        _captchaShown = true;
        Log("reCAPTCHA detected (" + via + ") — bringing browser to foreground.", LogLevel.Warning);

        try
        {
            _timeoutCts?.CancelAfter(CaptchaSolveWindow); // a human gets this long; nobody there = the scan moves on
            _form.BeginInvoke(() =>
            {
                try
                {
                    if (_barLabel != null) _barLabel.Text = Strings.CaptchaBarPrompt + "   " + TorService.StatusLine();
                    if (_torBtn != null) _torBtn.Text = TorService.IsActive ? Strings.CaptchaBtnNewCircuit : Strings.CaptchaBtnUseTor;
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
            _timeoutCts?.CancelAfter(FetchTimeout); // safety net for the re-fetch only
            Log("User reports reCAPTCHA solved — retrying lookup.", LogLevel.Info);
            _web!.CoreWebView2.Navigate(_currentUrl); // re-fetch with the now-valid session
        }
        catch (Exception ex) { Log("Solve-retry failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>The captcha bar's Tor button: switch Tor on when it is off, take a new exit address
    /// when it is already on. Either way the lookup is dropped so it restarts on the new route.</summary>
    static void OnTorButtonClicked()
    {
        var pending = _pending;
        try { if (_torBtn != null) { _torBtn.Enabled = false; _torBtn.Text = Strings.CaptchaBtnTorWorking; } }
        catch (Exception ex) { Log("Tor button state failed: " + ex.Message, LogLevel.Warning); }

        _ = Task.Run(async () =>
        {
            bool ok;
            try
            {
                if (TorService.IsActive)
                {
                    ok = await TorService.NewCircuitAsync();
                }
                else
                {
                    ok = await TorService.EnableAsync();
                    if (ok)
                    {
                        Settings.UseTor.Value = true;
                        SettingsManager.SaveSettings();
                        VtHttpClientFactory.Invalidate();
                    }
                }
                if (ok) InvalidateSession("captcha bar");
                UiStatusHub.Report(Strings.StatusSourceTor,
                    ok ? TorService.StatusLine() : string.Format(Strings.TorAutoEnableFailedFormat, TorService.LastError ?? "?"),
                    ok ? StatusSeverity.Info : StatusSeverity.Warning);
            }
            catch (Exception ex) { Log("Captcha-bar Tor action failed: " + ex, LogLevel.Error); ok = false; }

            try
            {
                _form?.BeginInvoke(() =>
                {
                    try
                    {
                        if (_torBtn != null) { _torBtn.Enabled = true; _torBtn.Text = TorService.IsActive ? Strings.CaptchaBtnNewCircuit : Strings.CaptchaBtnUseTor; }
                        if (_barLabel != null) _barLabel.Text = Strings.CaptchaBarPrompt + "   " + TorService.StatusLine();
                    }
                    catch (Exception ex) { Log("Tor button refresh failed: " + ex.Message, LogLevel.Warning); }
                });
            }
            catch (Exception ex) { Log("Tor button refresh dispatch failed: " + ex.Message, LogLevel.Warning); }

            // Give this lookup back to the caller: it will come round again on the new route, through a
            // freshly built browser (the old profile still holds the blocked address' cookie).
            if (ok) pending?.TrySetResult(null);
        });
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
