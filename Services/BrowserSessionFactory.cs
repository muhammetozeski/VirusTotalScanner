using System.Collections.Concurrent;
using System.Drawing;
using System.Globalization;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace VirusTotalScanner;

/// <summary>Randomized per-attempt browser identity (never contains the application name).</summary>
internal readonly record struct BrowserFingerprint(string UserAgent, string AcceptLanguage, int Width, int Height)
{
    static readonly string[] Languages =
    [
        "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
        "nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7",
        "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
        "tr-TR,tr;q=0.9,en;q=0.8",
    ];

    static readonly (int W, int H)[] Viewports =
    [
        (1280, 800), (1366, 768), (1440, 900), (1536, 864), (1600, 900), (1200, 820), (1152, 864),
    ];

    public static BrowserFingerprint Random()
    {
        var vp = Viewports[System.Random.Shared.Next(Viewports.Length)];
        return new BrowserFingerprint(
            UserAgentPool.PickChromiumWindows(),
            Languages[System.Random.Shared.Next(Languages.Length)],
            vp.W,
            vp.H);
    }
}

/// <summary>Outcome of one isolated, zero-cookie browser lookup attempt.</summary>
internal enum BrowserAttemptOutcome
{
    Report,                  // HTTP 200 JSON payload captured
    NotFound,                // definitive HTTP 404 from /ui/files/<hash>
    Challenged,              // reCAPTCHA / 429 / 403 blocked (or puzzle unanswered / captcha window busy)
    CaptchaSolvedButFailed,  // user solved captcha, yet the subsequent fetch still failed / timed out / 429'd
    UserSwitchedToApi,       // user explicitly clicked "API anahtarıyla devam et" on the captcha bar
    TimedOut,                // navigation or API XHR timed out
    NetworkError,            // DNS / TLS / proxy / socket failure
    NoRuntime,               // WebView2 runtime unavailable or init failed
    Cancelled,
}

internal readonly record struct BrowserAttemptResult(
    string? Json,
    BrowserAttemptOutcome Outcome,
    double UserWaitSeconds,
    bool CaptchaTriggered,
    bool AutoClickPassed,
    string Detail);

/// <summary>
/// Manages up to <see cref="HardMaxCacheSlots"/> (150) isolated WebView2 cache profile directories and
/// creates a brand-new, zero-cookie, InPrivate WebView2 browser session for EVERY lookup attempt.
///
/// Key guarantees:
///   1) No cookies, LocalStorage, IndexedDB, or session tokens are ever persisted or shared across lookups
///      (every session runs InPrivate + clears profile storage before navigation and disposes on exit).
///   2) Up to 150 cache slots can exist under DataFolder\BrowserCache\slot-XXX; a "wipe full identity"
///      resistance step retires the old slot and opens a fresh directory from the 150-slot pool.
///   3) Captcha handling tries a real CDP center-click on both api2/anchor and enterprise/anchor checkboxes
///      first; only when an image puzzle appears is the single foreground window shown to the user.
///   4) Even if the user solves a captcha and the connection still fails, the session reports
///      <see cref="BrowserAttemptOutcome.CaptchaSolvedButFailed"/> so the calling QueryCell keeps resisting.
/// </summary>
internal static class BrowserSessionFactory
{
    /// <summary>Maximum number of browser cache profile directories allowed on disk.</summary>
    public const int HardMaxCacheSlots = 150;

    /// <summary>Default concurrency ceiling when <see cref="Settings.KeylessBrowserPool"/> is 0 (auto),
    /// balancing speed against Chromium RAM usage while still allowing explicit settings up to 150.</summary>
    const int AutoMaxConcurrentBrowsers = 4;

    static readonly object _slotLock = new();
    static readonly HashSet<int> _inUseSlots = [];
    static readonly Dictionary<int, long> _slotLastUsedSeq = [];
    static long _slotSeq;
    static int _slotCursor;
    static int _activeBrowserCount;

    static SemaphoreSlim _concurrencyGate = new(AutoMaxConcurrentBrowsers, HardMaxCacheSlots);
    static int _builtConcurrency = AutoMaxConcurrentBrowsers;

    /// <summary>Only one browser window at a time may take the foreground for human captcha solving.</summary>
    internal static readonly SemaphoreSlim CaptchaWindowGate = new(1, 1);

    /// <summary>Active ephemeral sessions (for clean shutdown).</summary>
    static readonly ConcurrentDictionary<long, EphemeralBrowserSession> ActiveSessions = new();
    static long _sessionSeq;

    static string CacheRoot => ConfigPathResolver.BrowserCacheFolder;

    public static bool IsRuntimeAvailable
    {
        get { try { return !string.IsNullOrEmpty(CoreWebView2Environment.GetAvailableBrowserVersionString()); } catch { return false; } }
    }

    public static int ConfiguredCacheSlots => Math.Clamp(Settings.BrowserCacheSlots.Value, 1, HardMaxCacheSlots);

    public static int DesiredConcurrency()
    {
        if (GuiScrapeService.ProbeMode) return 1;
        int v = Settings.KeylessBrowserPool.Value;
        if (v <= 0) return Math.Clamp(Settings.MaxConcurrentScans.Value, 2, AutoMaxConcurrentBrowsers);
        return Math.Clamp(v, 1, HardMaxCacheSlots);
    }

    /// <summary>Runs one completely fresh, zero-cookie browser attempt on the requested route and fingerprint.</summary>
    public static async Task<BrowserAttemptResult> RunAttemptAsync(
        string hash,
        string suffix,
        string pageUrl,
        NetworkRoute route,
        BrowserFingerprint fingerprint,
        bool wipeProfileSlot,
        bool allowUserCaptcha,
        TimeSpan maxQueueWait,
        CancellationToken ct)
    {
        if (!IsRuntimeAvailable)
            return new BrowserAttemptResult(null, BrowserAttemptOutcome.NoRuntime, 0, false, false, "WebView2 yok");

        SemaphoreSlim gate;
        lock (_slotLock)
        {
            int desired = DesiredConcurrency();
            if (desired != _builtConcurrency && _activeBrowserCount == 0)
            {
                _concurrencyGate = new SemaphoreSlim(desired, HardMaxCacheSlots);
                _builtConcurrency = desired;
            }
            gate = _concurrencyGate;
        }

        if (!await gate.WaitAsync(maxQueueWait, ct))
            return new BrowserAttemptResult(null, BrowserAttemptOutcome.TimedOut, 0, false, false, "tarayıcı slotu meşgul");

        int slot = -1;
        string? profileDir = null;
        long sid = Interlocked.Increment(ref _sessionSeq);
        EphemeralBrowserSession? session = null;
        try
        {
            lock (_slotLock)
            {
                _activeBrowserCount++;
                slot = AcquireCacheSlotLocked(wipeProfileSlot, out profileDir);
            }

            if (wipeProfileSlot && profileDir != null)
                TryWipeDirectory(profileDir);

            session = new EphemeralBrowserSession(sid, slot, profileDir!, route, fingerprint, allowUserCaptcha);
            ActiveSessions[sid] = session;
            return await session.ExecuteAsync(hash, suffix, pageUrl, ct);
        }
        catch (OperationCanceledException)
        {
            return new BrowserAttemptResult(null, BrowserAttemptOutcome.Cancelled, 0, false, false, "iptal");
        }
        catch (Exception ex)
        {
            Log($"BrowserSession #{sid} failed: {ex.Message}", LogLevel.Warning);
            return new BrowserAttemptResult(null, BrowserAttemptOutcome.NetworkError, 0, false, false, ex.Message);
        }
        finally
        {
            ActiveSessions.TryRemove(sid, out _);
            try { session?.Dispose(); } catch { }
            lock (_slotLock)
            {
                if (slot >= 0) _inUseSlots.Remove(slot);
                _activeBrowserCount = Math.Max(0, _activeBrowserCount - 1);
            }
            gate.Release();
            if (wipeProfileSlot && profileDir != null)
                ScheduleDirectoryWipe(profileDir);
        }
    }

    /// <summary>Retires all existing cache directories in the background (triggered by hard reset / unstick).</summary>
    public static void WipeAllIdleCacheSlots()
    {
        _ = Task.Run(() =>
        {
            try
            {
                if (!Directory.Exists(CacheRoot)) return;
                HashSet<int> busy;
                lock (_slotLock) busy = [.. _inUseSlots];
                foreach (var dir in new DirectoryInfo(CacheRoot).EnumerateDirectories("slot-*"))
                {
                    if (int.TryParse(dir.Name.AsSpan(5), out int n) && busy.Contains(n)) continue;
                    TryWipeDirectory(dir.FullName);
                }
            }
            catch (Exception ex) { Log("BrowserCache sweep failed: " + ex.Message, LogLevel.Debug); }
        });
    }

    public static void Shutdown()
    {
        foreach (var kv in ActiveSessions.ToArray())
        {
            try { kv.Value.Dispose(); } catch { }
        }
        ActiveSessions.Clear();
    }

    static int AcquireCacheSlotLocked(bool preferFresh, out string dir)
    {
        int cap = ConfiguredCacheSlots;
        // Pick the least-recently-used idle slot within [1..cap], rotating across all 150 slots.
        int best = -1;
        long bestSeq = long.MaxValue;
        for (int i = 0; i < cap; i++)
        {
            int candidate = ((_slotCursor + i) % cap) + 1;
            if (_inUseSlots.Contains(candidate)) continue;
            long usedSeq = _slotLastUsedSeq.GetValueOrDefault(candidate, 0);
            if (preferFresh && usedSeq == 0) { best = candidate; break; }
            if (usedSeq < bestSeq) { bestSeq = usedSeq; best = candidate; if (usedSeq == 0) break; }
        }
        if (best < 0) best = (_slotCursor % cap) + 1;
        _slotCursor = best % cap;
        _inUseSlots.Add(best);
        _slotLastUsedSeq[best] = ++_slotSeq;
        dir = Path.Combine(CacheRoot, $"slot-{best:D3}");
        return best;
    }

    static void TryWipeDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
        }
        catch { /* WebView2 child process may hold lock briefly */ }
    }

    static void ScheduleDirectoryWipe(string path)
    {
        _ = Task.Run(async () =>
        {
            for (int i = 0; i < 6; i++)
            {
                await Task.Delay(750);
                try
                {
                    if (!Directory.Exists(path)) return;
                    Directory.Delete(path, recursive: true);
                    return;
                }
                catch { }
            }
        });
    }
}

/// <summary>
/// One disposable, zero-cookie WebView2 browser instance built for a single lookup attempt.
/// Runs on its own STA thread with InPrivate mode enabled, tries CDP center-click on reCAPTCHA
/// before showing a window to the user, and tears itself down completely on completion.
/// </summary>
internal sealed class EphemeralBrowserSession : IDisposable
{
    readonly long _id;
    readonly int _slot;
    readonly string _profileDir;
    readonly NetworkRoute _route;
    readonly BrowserFingerprint _fp;
    readonly bool _allowUserCaptcha;

    Thread? _thread;
    Form? _form;
    WebView2? _web;
    Panel? _bar;
    Label? _barLabel;
    readonly List<CoreWebView2Frame> _frames = [];

    TaskCompletionSource<string?>? _pending;
    TaskCompletionSource<bool>? _navDone;
    CancellationTokenSource? _timeoutCts;

    string _targetHash = "";
    string _targetSuffix = "";
    string _currentUrl = "";

    volatile bool _disposed;
    volatile bool _captchaShown;
    volatile bool _autoSolving;
    volatile bool _autoSolveTried;
    volatile bool _autoClickPassed;
    volatile bool _challengeSeen;
    volatile bool _userSolvedOnce;
    volatile bool _userSwitchedToApi;
    volatile bool _navFailed;
    volatile string _lastNavError = "";
    volatile int _lastHttpCode;
    int _holdsCaptchaGate;
    readonly System.Diagnostics.Stopwatch _userWaitClock = new();

    static readonly TimeSpan CaptchaSolveWindow = TimeSpan.FromMinutes(3);

    TimeSpan FetchTimeout => _route.IsTor ? TimeSpan.FromSeconds(110) : TimeSpan.FromSeconds(38);

    public EphemeralBrowserSession(
        long id, int slot, string profileDir, NetworkRoute route, BrowserFingerprint fp, bool allowUserCaptcha)
    {
        _id = id;
        _slot = slot;
        _profileDir = profileDir;
        _route = route;
        _fp = fp;
        _allowUserCaptcha = allowUserCaptcha;
    }

    public async Task<BrowserAttemptResult> ExecuteAsync(string hash, string suffix, string pageUrl, CancellationToken ct)
    {
        _targetHash = hash;
        _targetSuffix = suffix;
        _currentUrl = pageUrl;

        bool started = await StartFreshBrowserAsync(ct);
        if (!started)
            return new BrowserAttemptResult(null, BrowserAttemptOutcome.NoRuntime, 0, false, false, "WebView2 başlatılamadı");

        var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending = tcs;

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _timeoutCts = timeout;
        timeout.CancelAfter(FetchTimeout);

        try
        {
            Navigate(pageUrl, tcs);

            string? json;
            using (timeout.Token.Register(() => tcs.TrySetResult(null)))
                json = await tcs.Task;

            _userWaitClock.Stop();
            HideBrowser();

            if (ct.IsCancellationRequested)
                return new BrowserAttemptResult(null, BrowserAttemptOutcome.Cancelled, _userWaitClock.Elapsed.TotalSeconds, _challengeSeen, _autoClickPassed, "iptal");

            if (!string.IsNullOrEmpty(json))
                return new BrowserAttemptResult(json, BrowserAttemptOutcome.Report, _userWaitClock.Elapsed.TotalSeconds, _challengeSeen, _autoClickPassed, "200 OK");

            if (_userSwitchedToApi)
                return new BrowserAttemptResult(null, BrowserAttemptOutcome.UserSwitchedToApi, _userWaitClock.Elapsed.TotalSeconds, true, false, "kullanıcı API seçti");

            // If VT returned a definitive HTTP 404 (even after passing a captcha), treat it as NotFound!
            if (_lastHttpCode == 404)
                return new BrowserAttemptResult(null, BrowserAttemptOutcome.NotFound, _userWaitClock.Elapsed.TotalSeconds, _challengeSeen, _autoClickPassed, "404 NotFound");

            if (_userSolvedOnce)
                return new BrowserAttemptResult(null, BrowserAttemptOutcome.CaptchaSolvedButFailed, _userWaitClock.Elapsed.TotalSeconds, true, false,
                    $"captcha çözüldü ama bağlantı/yanıt başarısız (HTTP {_lastHttpCode})");

            if (_challengeSeen || _lastHttpCode is 429 or 403)
                return new BrowserAttemptResult(null, BrowserAttemptOutcome.Challenged, _userWaitClock.Elapsed.TotalSeconds, true, false,
                    $"engellendi (HTTP {_lastHttpCode})");

            if (_navFailed)
                return new BrowserAttemptResult(null, BrowserAttemptOutcome.NetworkError, _userWaitClock.Elapsed.TotalSeconds, false, false,
                    $"ağ hatası ({_lastNavError})");

            if (timeout.IsCancellationRequested)
                return new BrowserAttemptResult(null, BrowserAttemptOutcome.TimedOut, _userWaitClock.Elapsed.TotalSeconds, _challengeSeen, false, "zaman aşımı");

            return new BrowserAttemptResult(null, BrowserAttemptOutcome.NetworkError, _userWaitClock.Elapsed.TotalSeconds, false, false, "boş yanıt");
        }
        finally
        {
            _pending = null;
            _timeoutCts = null;
            ReleaseCaptchaGate();
            Dispose();
        }
    }

    Task<bool> StartFreshBrowserAsync(CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var reg = ct.Register(() => tcs.TrySetResult(false));

        _thread = new Thread(() =>
        {
            try
            {
                ApplicationConfiguration.Initialize();
                _form = new Form
                {
                    Width = _fp.Width,
                    Height = _fp.Height,
                    ShowInTaskbar = false,
                    Opacity = 0,
                    FormBorderStyle = FormBorderStyle.None,
                    StartPosition = FormStartPosition.Manual,
                    Location = new Point(-4000, -4000),
                    Text = Strings.CaptchaWindowTitle,
                };
                _form.FormClosing += (_, e) =>
                {
                    if (_disposed) return;
                    e.Cancel = true;
                    _pending?.TrySetResult(null);
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
                        Directory.CreateDirectory(_profileDir);
                        var args = new List<string>
                        {
                            "--disable-blink-features=AutomationControlled",
                            "--no-first-run",
                            "--disable-sync",
                            "--disable-background-networking",
                        };
                        if (!string.IsNullOrEmpty(_route.ProxyUrl))
                            args.Add($"--proxy-server=\"{_route.ProxyUrl}\"");

                        var envOpts = new CoreWebView2EnvironmentOptions
                        {
                            AdditionalBrowserArguments = string.Join(" ", args),
                            Language = _fp.AcceptLanguage.Split(',')[0],
                        };
                        var env = await CoreWebView2Environment.CreateAsync(null, _profileDir, envOpts);

                        // Ephemeral InPrivate profile: zero cookies or site storage ever persisted to disk.
                        var ctrlOpts = env.CreateCoreWebView2ControllerOptions();
                        ctrlOpts.IsInPrivateModeEnabled = true;
                        ctrlOpts.ProfileName = $"ephemeral_{_id}";

                        await _web.EnsureCoreWebView2Async(env, ctrlOpts);
                        var core = _web.CoreWebView2;

                        // Defensive wipe of any residual in-memory cookies/storage before the first navigation.
                        try { core.CookieManager.DeleteAllCookies(); } catch { }
                        try
                        {
                            await core.Profile.ClearBrowsingDataAsync(
                                CoreWebView2BrowsingDataKinds.Cookies |
                                CoreWebView2BrowsingDataKinds.LocalStorage |
                                CoreWebView2BrowsingDataKinds.IndexedDb |
                                CoreWebView2BrowsingDataKinds.WebSql |
                                CoreWebView2BrowsingDataKinds.AllDomStorage);
                        }
                        catch { }

                        core.Settings.UserAgent = _fp.UserAgent;
                        core.Settings.AreDefaultScriptDialogsEnabled = false;
                        core.Settings.IsStatusBarEnabled = false;
                        try
                        {
                            await core.AddScriptToExecuteOnDocumentCreatedAsync(
                                "try{Object.defineProperty(navigator,'webdriver',{get:()=>undefined});}catch(e){}");
                        }
                        catch { }

                        core.WebResourceResponseReceived += OnResponse;
                        core.NavigationCompleted += OnNavigationCompleted;
                        core.FrameCreated += OnFrameCreated;
                        tcs.TrySetResult(true);
                    }
                    catch (Exception ex)
                    {
                        Log($"Ephemeral WebView2 #{_id} (slot {_slot}, {_route.Label}) init failed: {ex.Message}", LogLevel.Warning);
                        tcs.TrySetResult(false);
                    }
                };

                Application.Run(_form);
            }
            catch (Exception ex)
            {
                Log($"Ephemeral WebView2 host thread #{_id} failed: {ex.Message}", LogLevel.Warning);
                tcs.TrySetResult(false);
            }
            finally { reg.Dispose(); }
        })
        { IsBackground = true, Name = $"vt-cell-{_id}" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        return tcs.Task;
    }

    void Navigate(string url, TaskCompletionSource<string?>? failTo)
    {
        try
        {
            _navDone = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _form?.BeginInvoke(() =>
            {
                try
                {
                    if (_web?.CoreWebView2 == null) { failTo?.TrySetResult(null); _navDone?.TrySetResult(false); return; }
                    _web.CoreWebView2.Navigate(url);
                }
                catch (Exception ex)
                {
                    failTo?.TrySetResult(null);
                    _navDone?.TrySetResult(false);
                    Log($"BrowserSession #{_id} navigate failed: {ex.Message}", LogLevel.Warning);
                }
            });
        }
        catch (Exception ex)
        {
            failTo?.TrySetResult(null);
            _navDone?.TrySetResult(false);
            Log($"BrowserSession #{_id} navigate dispatch failed: {ex.Message}", LogLevel.Warning);
        }
    }

    void OnFrameCreated(object? sender, CoreWebView2FrameCreatedEventArgs e)
    {
        try
        {
            var frame = e.Frame;
            lock (_frames) _frames.Add(frame);
            frame.Destroyed += (s, _) => { lock (_frames) _frames.Remove((CoreWebView2Frame)s!); };
        }
        catch { }
    }

    void BuildCaptchaBar()
    {
        _bar = new Panel { Dock = DockStyle.Top, Height = 46, BackColor = Color.FromArgb(0xE3, 0xB3, 0x41), Visible = false };
        _barLabel = new Label
        {
            Text = Strings.CaptchaBarPrompt + $"   [{_route.Label}]",
            ForeColor = Color.Black,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Font = new Font("Segoe UI", 10f, FontStyle.Bold),
        };
        var solvedBtn = MakeBarButton(Strings.CaptchaBtnSolved, 170);
        solvedBtn.Click += (_, _) => OnSolvedClicked();
        var apiBtn = MakeBarButton(Strings.CaptchaBtnSwitchToApi, 160);
        apiBtn.Click += (_, _) => { _userSwitchedToApi = true; _pending?.TrySetResult(null); HideBrowser(); };
        var nextRouteBtn = MakeBarButton(Strings.CaptchaBtnNextRoute, 170);
        nextRouteBtn.Click += (_, _) => { _pending?.TrySetResult(null); HideBrowser(); };

        _bar.Controls.Add(_barLabel);
        _bar.Controls.Add(solvedBtn);
        _bar.Controls.Add(nextRouteBtn);
        _bar.Controls.Add(apiBtn);
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

    async void OnResponse(object? sender, CoreWebView2WebResourceResponseReceivedEventArgs e)
    {
        var pending = _pending;
        if (pending == null || pending.Task.IsCompleted) return;
        try
        {
            string path = e.Request.Uri.Split('?')[0].TrimEnd('/');
            if (!path.EndsWith("/ui/files/" + _targetHash + _targetSuffix, StringComparison.OrdinalIgnoreCase)) return;

            int code = e.Response.StatusCode;
            _lastHttpCode = code;
            Log($"Cell browser #{_id} ({_route.Label}, slot {_slot}) <- HTTP {code} for {path}", LogLevel.Info);

            if (code == 200)
            {
                var stream = await e.Response.GetContentAsync();
                if (stream == null) { pending.TrySetResult(null); return; }
                using var r = new StreamReader(stream);
                string body = await r.ReadToEndAsync();
                pending.TrySetResult(body);
                return;
            }

            if (code == 404)
            {
                pending.TrySetResult(null);
                return;
            }

            if (code is 429 or 403)
            {
                // If the user ALREADY solved a captcha in this session and VT still returned 429/403,
                // don't trap them in a loop — end this attempt so QueryCell switches identity/route.
                if (_userSolvedOnce)
                {
                    Log($"Cell browser #{_id}: still HTTP {code} after captcha solve — handing back to resistance engine.", LogLevel.Warning);
                    pending.TrySetResult(null);
                    return;
                }
                HandleCaptcha("http-" + code);
                return;
            }

            // 5xx or other transient status: let resistance engine retry cleanly.
            pending.TrySetResult(null);
        }
        catch (Exception ex)
        {
            Log($"Cell browser #{_id} response error: {ex.Message}", LogLevel.Warning);
            pending.TrySetResult(null);
        }
    }

    async void OnNavigationCompleted(object? sender, CoreWebView2NavigationCompletedEventArgs e)
    {
        _navDone?.TrySetResult(e.IsSuccess);
        if (!e.IsSuccess && e.WebErrorStatus != CoreWebView2WebErrorStatus.OperationCanceled)
        {
            _navFailed = true;
            _lastNavError = e.WebErrorStatus.ToString();
            Log($"Cell browser #{_id} ({_route.Label}) nav failed: {e.WebErrorStatus} (http={e.HttpStatusCode})", LogLevel.Warning);
            if (_pending is { Task.IsCompleted: false } && !_captchaShown && !_autoSolving)
                _pending.TrySetResult(null);
            return;
        }

        if (_pending == null || _pending.Task.IsCompleted || _captchaShown || _autoSolving || _web == null) return;
        try
        {
            if (await HasVisibleChallengeAsync()) HandleCaptcha("dom-visible");
        }
        catch { }
    }

    /// <summary>Checks main document and Shadow DOM roots for a genuinely visible reCAPTCHA challenge.</summary>
    async Task<bool> HasVisibleChallengeAsync()
    {
        if (_web == null) return false;
        const string js =
            "(function(){try{" +
            "function walk(root){" +
            "  var ifr=root.querySelectorAll('iframe');" +
            "  for(var i=0;i<ifr.length;i++){" +
            "    var s=(ifr[i].src||'').toLowerCase();" +
            "    if(s.indexOf('api2/bframe')>=0||s.indexOf('enterprise/bframe')>=0){" +
            "      var r=ifr[i].getBoundingClientRect();" +
            "      if(r.width>100&&r.height>100)return true;" +
            "    }" +
            "  }" +
            "  if(root.querySelector('#rc-imageselect,.rc-imageselect,.g-recaptcha-bubble-arrow'))return true;" +
            "  var all=root.querySelectorAll('*');" +
            "  for(var j=0;j<all.length;j++){if(all[j].shadowRoot&&walk(all[j].shadowRoot))return true;}" +
            "  return false;" +
            "}" +
            "if(document.title&&/are you human|verify you are|complete the captcha/i.test(document.title))return true;" +
            "return walk(document);" +
            "}catch(e){return false;}})()";
        string res = await RunOnUiAsync(() => _web!.CoreWebView2.ExecuteScriptAsync(js));
        return res.Contains("true", StringComparison.OrdinalIgnoreCase);
    }

    void HandleCaptcha(string via)
    {
        if (_captchaShown || _autoSolving || _disposed) return;
        _challengeSeen = true;
        if (GuiScrapeService.ProbeMode)
        {
            _pending?.TrySetResult(null);
            return;
        }
        if (!Settings.CaptchaAutoClick || _autoSolveTried)
        {
            if (_allowUserCaptcha && !GuiScrapeService.HeadlessMode) ShowCaptcha(via);
            else _pending?.TrySetResult(null);
            return;
        }

        _autoSolveTried = true;
        _autoSolving = true;
        _timeoutCts?.CancelAfter(Timeout.InfiniteTimeSpan);

        _ = Task.Run(async () =>
        {
            bool solved = false;
            try { solved = await TryAutoCenterClickAsync(); }
            catch (Exception ex) { Log($"Cell browser #{_id} captcha center-click failed: {ex.Message}", LogLevel.Warning); }
            finally
            {
                _autoSolving = false;
                if (solved)
                {
                    _autoClickPassed = true;
                    Log($"Cell browser #{_id}: reCAPTCHA single center-click succeeded.", LogLevel.Info);
                    _timeoutCts?.CancelAfter(FetchTimeout);
                }
                else if (_pending is { Task.IsCompleted: false })
                {
                    if (_allowUserCaptcha && !GuiScrapeService.HeadlessMode)
                        ShowCaptcha(via + "+puzzle");
                    else
                        _pending.TrySetResult(null);
                }
            }
        });
    }

    /// <summary>
    /// Attempts a single human-like center click on the reCAPTCHA "I am not a robot" checkbox using
    /// WebView2 CDP Input.dispatchMouseEvent (falling back to DOM click inside anchor frames).
    /// Supports both recaptcha/api2/anchor and recaptcha/enterprise/anchor, including Shadow DOM hosts.
    /// </summary>
    async Task<bool> TryAutoCenterClickAsync()
    {
        var pending = _pending;
        if (pending == null || _web == null) return false;

        // First check if an anchor iframe is ALREADY rendered in the current page; reload only if absent.
        var box = await FindAnchorCheckboxCenterAsync();
        if (box == null)
        {
            Navigate(_currentUrl, null);
            var nav = _navDone;
            if (nav != null)
            {
                var done = await Task.WhenAny(nav.Task, Task.Delay(TimeSpan.FromSeconds(18)));
                if (done != nav.Task) return false;
            }
            if (pending.Task.IsCompleted) return true;
        }

        var deadline = DateTime.UtcNow.AddSeconds(16);
        bool clicked = false;
        while (DateTime.UtcNow < deadline && !pending.Task.IsCompleted && !_disposed)
        {
            // 1) Try CDP real mouse click at the exact center of the checkbox
            if (!clicked)
            {
                box = await FindAnchorCheckboxCenterAsync();
                if (box is { } pt)
                {
                    await DispatchRealMouseClickAsync(pt.X, pt.Y);
                    clicked = true;
                    Log($"Cell browser #{_id}: dispatched CDP center-click at ({pt.X:0},{pt.Y:0}).", LogLevel.Debug);
                }
            }

            // 2) Inspect / fallback-click inside all anchor frames (api2/anchor and enterprise/anchor)
            string state = await InspectOrClickAnchorFramesAsync(allowDomClick: !clicked);
            if (state is "already" or "checked") { clicked = true; break; }
            if (state == "clicked") clicked = true;

            if (clicked && await HasVisibleChallengeAsync())
            {
                Log($"Cell browser #{_id}: image puzzle appeared after center-click — handing to user.", LogLevel.Info);
                return false;
            }
            await Task.Delay(450);
        }

        if (!clicked) return false;
        if (await HasVisibleChallengeAsync()) return false;
        if (pending.Task.IsCompleted) return true;

        // Checkbox went green without a puzzle: give SPA 2s to auto-refetch, otherwise re-navigate.
        if (await Task.WhenAny(pending.Task, Task.Delay(2000)) == pending.Task)
            return pending.Task.Result != null;

        Navigate(_currentUrl, null);
        var finish = await Task.WhenAny(pending.Task, Task.Delay(TimeSpan.FromSeconds(22)));
        return finish == pending.Task && pending.Task.Result != null;
    }

    /// <summary>Finds the viewport center coordinates of the reCAPTCHA checkbox (inside the anchor iframe,
    /// walking Shadow DOM trees as well).</summary>
    async Task<(double X, double Y)?> FindAnchorCheckboxCenterAsync()
    {
        if (_web == null) return null;
        const string js =
            "(function(){try{" +
            "function find(root){" +
            "  var ifr=root.querySelectorAll('iframe');" +
            "  for(var i=0;i<ifr.length;i++){" +
            "    var s=(ifr[i].src||'').toLowerCase();" +
            "    if(s.indexOf('recaptcha/api2/anchor')>=0||s.indexOf('recaptcha/enterprise/anchor')>=0){" +
            "      var r=ifr[i].getBoundingClientRect();" +
            "      if(r.width>=100&&r.height>=40){" +
            "        return JSON.stringify({x:r.left+28,y:r.top+(r.height/2)});" +
            "      }" +
            "    }" +
            "  }" +
            "  var all=root.querySelectorAll('*');" +
            "  for(var j=0;j<all.length;j++){if(all[j].shadowRoot){var hit=find(all[j].shadowRoot);if(hit)return hit;}}" +
            "  return '';" +
            "}" +
            "return find(document);" +
            "}catch(e){return '';}})()";

        string raw = await RunOnUiAsync(() => _web!.CoreWebView2.ExecuteScriptAsync(js));
        try
        {
            string? unquoted = JsonSerializer.Deserialize<string>(raw);
            if (string.IsNullOrWhiteSpace(unquoted)) return null;
            using var doc = JsonDocument.Parse(unquoted);
            double x = doc.RootElement.GetProperty("x").GetDouble();
            double y = doc.RootElement.GetProperty("y").GetDouble();
            if (x > 0 && y > 0) return (x, y);
        }
        catch { }
        return null;
    }

    async Task DispatchRealMouseClickAsync(double x, double y)
    {
        if (_web == null) return;
        // Small natural offset (+/- 2px) around center of the 28x28 checkbox
        double jitterX = x + (System.Random.Shared.NextDouble() * 4.0 - 2.0);
        double jitterY = y + (System.Random.Shared.NextDouble() * 4.0 - 2.0);
        string sx = jitterX.ToString("0.0", CultureInfo.InvariantCulture);
        string sy = jitterY.ToString("0.0", CultureInfo.InvariantCulture);
        string preX = Math.Max(1, jitterX - 18).ToString("0.0", CultureInfo.InvariantCulture);
        string preY = Math.Max(1, jitterY - 9).ToString("0.0", CultureInfo.InvariantCulture);

        await RunOnUiAsync(() => _web!.CoreWebView2.CallDevToolsProtocolMethodAsync(
            "Input.dispatchMouseEvent", $"{{\"type\":\"mouseMoved\",\"x\":{preX},\"y\":{preY}}}"));
        await Task.Delay(55);
        await RunOnUiAsync(() => _web!.CoreWebView2.CallDevToolsProtocolMethodAsync(
            "Input.dispatchMouseEvent", $"{{\"type\":\"mouseMoved\",\"x\":{sx},\"y\":{sy}}}"));
        await Task.Delay(75);
        await RunOnUiAsync(() => _web!.CoreWebView2.CallDevToolsProtocolMethodAsync(
            "Input.dispatchMouseEvent", $"{{\"type\":\"mousePressed\",\"x\":{sx},\"y\":{sy},\"button\":\"left\",\"clickCount\":1}}"));
        await Task.Delay(65);
        await RunOnUiAsync(() => _web!.CoreWebView2.CallDevToolsProtocolMethodAsync(
            "Input.dispatchMouseEvent", $"{{\"type\":\"mouseReleased\",\"x\":{sx},\"y\":{sy},\"button\":\"left\",\"clickCount\":1}}"));
    }

    async Task<string> InspectOrClickAnchorFramesAsync(bool allowDomClick)
    {
        string js =
            "(function(){try{" +
            "var u=(location.href||'').toLowerCase();" +
            "if(u.indexOf('api2/anchor')<0&&u.indexOf('enterprise/anchor')<0)return 'skip';" +
            "var c=document.getElementById('recaptcha-anchor')||document.querySelector('.recaptcha-checkbox');" +
            "if(!c)return 'nochk';" +
            "if(c.getAttribute('aria-checked')==='true')return 'already';" +
            (allowDomClick ? "c.click();return c.getAttribute('aria-checked')==='true'?'checked':'clicked';" : "return 'unchecked';") +
            "}catch(e){return 'err';}})()";

        List<CoreWebView2Frame> frames;
        lock (_frames) frames = [.. _frames];
        string best = "none";
        foreach (var frame in frames)
        {
            try
            {
                string raw = await RunOnUiAsync(() => frame.ExecuteScriptAsync(js));
                string val = raw.Trim('"');
                if (val is "already" or "checked") return val;
                if (val == "clicked") best = "clicked";
            }
            catch { }
        }
        return best;
    }

    void ShowCaptcha(string via)
    {
        if (_captchaShown || _form == null || _bar == null || _disposed) return;

        // Wait briefly for the foreground captcha gate; if another cell already owns it, yield back
        // so this cell keeps progressing through alternate routes/identities instead of stalling.
        if (!BrowserSessionFactory.CaptchaWindowGate.Wait(1500))
        {
            Log($"Cell browser #{_id}: captcha ({via}) while another captcha window is open — yielding to resistance engine.", LogLevel.Info);
            _pending?.TrySetResult(null);
            return;
        }
        Interlocked.Exchange(ref _holdsCaptchaGate, 1);
        _captchaShown = true;
        _userWaitClock.Start();
        Log($"Cell browser #{_id} ({_route.Label}): showing captcha window ({via}).", LogLevel.Warning);

        try
        {
            _timeoutCts?.CancelAfter(CaptchaSolveWindow);
            _form.BeginInvoke(() =>
            {
                try
                {
                    if (_barLabel != null) _barLabel.Text = Strings.CaptchaBarPrompt + $"   [{_route.Label}]";
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
                catch (Exception ex) { Log($"ShowCaptcha UI #{_id} failed: {ex.Message}", LogLevel.Warning); }
            });

            // Auto-detect when the user finishes solving the puzzle so they don't even have to click "Çözdüm".
            _ = Task.Run(WatchUserSolveAsync);
        }
        catch (Exception ex) { Log($"ShowCaptcha #{_id} failed: {ex.Message}", LogLevel.Warning); }
    }

    async Task WatchUserSolveAsync()
    {
        while (_captchaShown && !_disposed && _pending is { Task.IsCompleted: false })
        {
            await Task.Delay(750);
            if (!_captchaShown || _disposed || _pending is not { Task.IsCompleted: false }) return;
            try
            {
                string state = await InspectOrClickAnchorFramesAsync(allowDomClick: false);
                if (state is "already" or "checked")
                {
                    Log($"Cell browser #{_id}: detected user solved reCAPTCHA automatically — re-fetching.", LogLevel.Info);
                    OnSolvedClicked();
                    return;
                }
            }
            catch { }
        }
    }

    void OnSolvedClicked()
    {
        if (_disposed) return;
        try
        {
            _userSolvedOnce = true;
            _captchaShown = false;
            _userWaitClock.Stop();
            _timeoutCts?.CancelAfter(FetchTimeout);
            _form?.BeginInvoke(() =>
            {
                try
                {
                    if (_bar != null) _bar.Visible = false;
                    _web?.CoreWebView2?.Navigate(_currentUrl);
                }
                catch { }
            });
        }
        catch (Exception ex) { Log($"Cell browser #{_id} solve-retry failed: {ex.Message}", LogLevel.Warning); }
    }

    Task<string> RunOnUiAsync(Func<Task<string>> action)
    {
        var form = _form;
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (_disposed || form == null || !form.IsHandleCreated) { tcs.TrySetResult(""); return tcs.Task; }
        try
        {
            form.BeginInvoke(async () =>
            {
                try { tcs.TrySetResult(await action() ?? ""); }
                catch { tcs.TrySetResult(""); }
            });
        }
        catch { tcs.TrySetResult(""); }
        return tcs.Task;
    }

    void ReleaseCaptchaGate()
    {
        if (Interlocked.Exchange(ref _holdsCaptchaGate, 0) == 1)
        {
            try { BrowserSessionFactory.CaptchaWindowGate.Release(); } catch { }
        }
    }

    void HideBrowser()
    {
        ReleaseCaptchaGate();
        var form = _form;
        if (form == null || _disposed) return;
        try
        {
            form.BeginInvoke(() =>
            {
                try
                {
                    if (_bar != null) _bar.Visible = false;
                    _captchaShown = false;
                    form.TopMost = false;
                    form.Opacity = 0;
                    form.ShowInTaskbar = false;
                    form.Hide();
                }
                catch { }
            });
        }
        catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        ReleaseCaptchaGate();
        var form = _form;
        var thread = _thread;
        try
        {
            form?.BeginInvoke(() =>
            {
                try { _web?.Dispose(); } catch { }
                try { form.Close(); } catch { }
            });
        }
        catch { }
        try { if (thread != null && thread != Thread.CurrentThread) thread.Join(TimeSpan.FromSeconds(4)); } catch { }
        lock (_frames) _frames.Clear();
        _form = null;
        _web = null;
        _thread = null;
    }
}
