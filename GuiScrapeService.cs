using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace VirusTotalScanner;

/// <summary>
/// Keyless VirusTotal lookup: drives a hidden WebView2 (real Chromium) to the public GUI page
/// and captures the page's own internal /ui/files/&lt;hash&gt; response — the same data the API
/// returns, but with NO API key and NO quota (reCAPTCHA is satisfied by the real browser
/// session). Slower than the API and dependent on the public site, so it's opt-in / used as a
/// fallback when no key is configured. Lookup-only: it cannot upload unknown files.
/// </summary>
internal static class GuiScrapeService
{
    static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };
    static readonly SemaphoreSlim _gate = new(1, 1);

    static Thread? _thread;
    static Form? _form;
    static WebView2? _web;
    static TaskCompletionSource<bool>? _initTcs;
    static volatile bool _initFailed;

    static string _targetHash = "";
    static TaskCompletionSource<string?>? _pending;

    /// <summary>True if the WebView2 runtime is present (keyless lookup is possible).</summary>
    public static bool IsRuntimeAvailable
    {
        get { try { return !string.IsNullOrEmpty(CoreWebView2Environment.GetAvailableBrowserVersionString()); } catch { return false; } }
    }

    /// <summary>Looks up a hash (sha256 preferred) via the GUI. Returns null if not found / blocked / timed out.</summary>
    public static async Task<VtFileReport?> LookupAsync(string hash, CancellationToken ct = default)
    {
        hash = hash.Trim().ToLowerInvariant();
        await _gate.WaitAsync(ct);
        try
        {
            if (!await EnsureReadyAsync()) return null;

            var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
            _targetHash = hash;
            _pending = tcs;

            Log("Keyless GUI lookup: " + hash, LogLevel.Info);
            _form!.BeginInvoke(() =>
            {
                try { _web!.CoreWebView2.Navigate("https://www.virustotal.com/gui/file/" + hash); }
                catch (Exception ex) { tcs.TrySetResult(null); Log("GUI navigate failed: " + ex.Message, LogLevel.Warning); }
            });

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(40));
            string? json;
            using (timeout.Token.Register(() => tcs.TrySetResult(null)))
                json = await tcs.Task;

            _pending = null;
            if (string.IsNullOrEmpty(json)) return null;

            var dto = JsonSerializer.Deserialize<VtResponse<VtFileData>>(json, JsonOpts);
            var report = VtApiClient.MapReport(dto?.Data?.Attributes);
            if (report != null) report.Sha256 ??= hash;
            return report;
        }
        catch (Exception ex) { Log("Keyless GUI lookup failed: " + ex.Message, LogLevel.Warning); return null; }
        finally { _gate.Release(); }
    }

    /// <summary>Closes the hidden browser cleanly (reduces Chromium shutdown noise on exit).</summary>
    public static void Shutdown()
    {
        try { _form?.BeginInvoke(() => { try { _web?.Dispose(); _form?.Close(); } catch { } }); } catch { }
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
                    Width = 1200,
                    Height = 900,
                    ShowInTaskbar = false,
                    Opacity = 0,
                    FormBorderStyle = FormBorderStyle.None,
                    StartPosition = FormStartPosition.Manual,
                    Location = new System.Drawing.Point(-4000, -4000),
                };
                _web = new WebView2 { Dock = DockStyle.Fill };
                _form.Controls.Add(_web);

                _form.Load += async (_, _) =>
                {
                    try
                    {
                        string userData = Path.Combine(ConfigPathResolver.DataFolder, "webview2");
                        Directory.CreateDirectory(userData);
                        var env = await CoreWebView2Environment.CreateAsync(null, userData);
                        await _web.EnsureCoreWebView2Async(env);
                        _web.CoreWebView2.WebResourceResponseReceived += OnResponse;
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

    static async void OnResponse(object? sender, CoreWebView2WebResourceResponseReceivedEventArgs e)
    {
        var pending = _pending;
        if (pending == null) return;
        try
        {
            string uri = e.Request.Uri.Split('?')[0].TrimEnd('/');
            if (!uri.EndsWith("/ui/files/" + _targetHash, StringComparison.OrdinalIgnoreCase)) return;

            if (e.Response.StatusCode != 200) { pending.TrySetResult(null); return; } // 404 not found / 429 blocked
            var stream = await e.Response.GetContentAsync();
            if (stream == null) { pending.TrySetResult(null); return; }
            using var r = new StreamReader(stream);
            pending.TrySetResult(await r.ReadToEndAsync());
        }
        catch { pending.TrySetResult(null); }
    }
}
