using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Runs a private <c>tor.exe</c> child process and exposes it as a SOCKS5 proxy for both network
/// paths of the app: the API <see cref="HttpClient"/> and the keyless WebView2 browser.
///
/// Why it exists: VirusTotal limits the keyless public UI per SOURCE IP. Once that limit is hit
/// every lookup comes back 429 / reCAPTCHA no matter how much key quota is left, and a full-disk
/// scan stops making progress. A new Tor circuit is a new exit IP, which resets that limit.
///
/// Ports are picked free at start (not the well-known 9050/9051) so an already-running Tor Browser
/// is never disturbed. The control port uses Tor's own cookie file, so no password is stored.
/// </summary>
internal static class TorService
{
    /// <summary>True while the proxy is up and traffic should go through it.</summary>
    public static bool IsActive { get; private set; }

    /// <summary>Bootstrap / start-up in progress.</summary>
    public static bool IsBusy { get; private set; }

    /// <summary>Last known exit-node address, or null when unknown.</summary>
    public static string? ExitIp { get; private set; }

    /// <summary>Last known exit-node country ("Almanya (DE)"), or null when unknown.</summary>
    public static string? ExitCountry { get; private set; }

    /// <summary>Last error text (start failure, circuit failure), or null.</summary>
    public static string? LastError { get; private set; }

    /// <summary>How many times the circuit has been rotated in this session.</summary>
    public static int CircuitCount { get; private set; }

    /// <summary>Raised (on a background thread) whenever any of the state above changes.</summary>
    public static event Action? StateChanged;

    /// <summary>The proxy URL for <see cref="WebProxy"/> / Chromium, or null when Tor is off.</summary>
    public static string? ProxyUrl => IsActive ? $"socks5://127.0.0.1:{_socksPort}" : null;

    static Process? _proc;
    static int _socksPort, _controlPort;
    static readonly SemaphoreSlim _gate = new(1, 1);
    static readonly List<string> _bootLog = [];

    // ---- discovery ----

    /// <summary>Every place tor.exe is looked for, in order. Public so the UI can show it when the
    /// binary is missing instead of just saying "not found".</summary>
    public static List<string> SearchedPaths()
    {
        var list = new List<string>();
        try
        {
            string configured = (Settings.TorExePath.Value ?? "").Trim().Trim('"');
            if (configured.Length > 0) list.Add(configured);
        }
        catch (Exception ex) { Log("Tor path setting read failed: " + ex.Message, LogLevel.Warning); }

        try { list.Add(Path.Combine(AppConstants.ThisExeFolder, "tor", "tor.exe")); } catch { }
        try { list.Add(Path.Combine(AppConstants.ThisExeFolder, "tor.exe")); } catch { }

        // scoop / winget / chocolatey shims and the usual Tor Browser layouts
        try
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            list.Add(Path.Combine(home, "scoop", "apps", "tor", "current", "tor", "tor.exe"));
            list.Add(Path.Combine(localApp, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"));
            list.Add(Path.Combine(home, "Desktop", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"));
            list.Add(@"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe");
            list.Add(@"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe");
        }
        catch (Exception ex) { Log("Tor well-known path build failed: " + ex.Message, LogLevel.Warning); }

        // Anything named tor.exe on PATH (scoop shims live there).
        try
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                try { list.Add(Path.Combine(dir, "tor.exe")); } catch { }
            }
        }
        catch (Exception ex) { Log("Tor PATH scan failed: " + ex.Message, LogLevel.Warning); }

        return list;
    }

    /// <summary>Resolves the tor binary, or null when it is nowhere to be found.</summary>
    public static string? FindTorExe()
    {
        foreach (var p in SearchedPaths())
        {
            try { if (!string.IsNullOrWhiteSpace(p) && File.Exists(p)) return ResolveShim(p); }
            catch (Exception ex) { Log($"Tor probe failed for '{p}': {ex.Message}", LogLevel.Warning); }
        }
        return null;
    }

    /// <summary>A scoop shim is a tiny launcher next to a "&lt;name&gt;.shim" file naming the real exe.
    /// Starting the shim works too, but the real binary gives us a clean child process to kill.</summary>
    static string ResolveShim(string exePath)
    {
        try
        {
            string shim = Path.ChangeExtension(exePath, ".shim");
            if (!File.Exists(shim)) return exePath;
            foreach (var line in File.ReadAllLines(shim))
            {
                int eq = line.IndexOf('=');
                if (eq <= 0 || !line[..eq].Trim().Equals("path", StringComparison.OrdinalIgnoreCase)) continue;
                string target = line[(eq + 1)..].Trim().Trim('"');
                if (File.Exists(target)) return target;
            }
        }
        catch (Exception ex) { Log("Tor shim resolve failed: " + ex.Message, LogLevel.Warning); }
        return exePath;
    }

    // ---- lifecycle ----

    /// <summary>Starts Tor (idempotent) and waits for bootstrap. Returns false with
    /// <see cref="LastError"/> set when the binary is missing or bootstrap fails.</summary>
    public static async Task<bool> EnableAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (IsActive && _proc is { HasExited: false }) return true;

            IsBusy = true; LastError = null; Raise();

            string? exe = FindTorExe();
            if (exe == null)
            {
                LastError = Strings.TorErrExeNotFound;
                Log("Tor could not be started: tor.exe not found. Looked at: " + string.Join(" | ", SearchedPaths().Take(8)), LogLevel.Error);
                return false;
            }

            _socksPort = FreePort();
            _controlPort = FreePort(_socksPort);
            string dataDir = Path.Combine(ConfigPathResolver.DataFolder, "tor-data");
            string torrc = Path.Combine(ConfigPathResolver.DataFolder, "torrc");

            try
            {
                Directory.CreateDirectory(dataDir);
                File.WriteAllText(torrc, BuildTorrc(exe, dataDir), new UTF8Encoding(false));
            }
            catch (Exception ex)
            {
                LastError = string.Format(Strings.TorErrConfigWriteFormat, ex.Message);
                Log("Tor config write failed: " + ex, LogLevel.Error);
                return false;
            }

            lock (_bootLog) _bootLog.Clear();
            try
            {
                var psi = new ProcessStartInfo(exe)
                {
                    Arguments = $"-f \"{torrc}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    WorkingDirectory = Path.GetDirectoryName(exe) ?? ConfigPathResolver.DataFolder,
                };
                _proc = Process.Start(psi);
                if (_proc == null)
                {
                    LastError = Strings.TorErrStartFailed;
                    Log("Tor start returned no process.", LogLevel.Error);
                    return false;
                }
                _proc.OutputDataReceived += (_, e) => OnTorLine(e.Data);
                _proc.ErrorDataReceived += (_, e) => OnTorLine(e.Data);
                _proc.BeginOutputReadLine();
                _proc.BeginErrorReadLine();
                Log($"Tor started (pid {_proc.Id}) socks={_socksPort} control={_controlPort} exe={exe}", LogLevel.Info);
            }
            catch (Exception ex)
            {
                LastError = string.Format(Strings.TorErrStartFailedFormat, ex.Message);
                Log("Tor process start failed: " + ex, LogLevel.Error);
                return false;
            }

            bool up = await WaitForBootstrapAsync(ct);
            if (!up)
            {
                LastError ??= Strings.TorErrBootstrapTimeout;
                Log("Tor bootstrap did not complete. Last lines: " + LastBootLines(), LogLevel.Error);
                KillProcess();
                return false;
            }

            IsActive = true;
            Log("Tor is ready; routing VirusTotal traffic through it.", LogLevel.Info);
            return true;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Log("Tor enable failed: " + ex, LogLevel.Error);
            return false;
        }
        finally
        {
            IsBusy = false;
            Raise();
            if (IsActive) _ = RefreshExitInfoAsync();
        }
    }

    /// <summary>Stops Tor and drops back to the direct connection.</summary>
    public static void Disable()
    {
        try
        {
            bool was = IsActive;
            IsActive = false;
            ExitIp = null; ExitCountry = null;
            KillProcess();
            if (was) Log("Tor disabled; back to the direct connection.", LogLevel.Info);
        }
        catch (Exception ex) { Log("Tor disable failed: " + ex.Message, LogLevel.Warning); }
        finally { Raise(); }
    }

    static void KillProcess()
    {
        var p = _proc;
        _proc = null;
        if (p == null) return;
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); }
        catch (Exception ex) { Log("Tor kill failed: " + ex.Message, LogLevel.Warning); }
        finally { try { p.Dispose(); } catch { } }
    }

    static string BuildTorrc(string torExe, string dataDir)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"SocksPort 127.0.0.1:{_socksPort}");
        sb.AppendLine($"ControlPort 127.0.0.1:{_controlPort}");
        sb.AppendLine("CookieAuthentication 1");
        sb.AppendLine($"DataDirectory {Quote(dataDir)}");
        sb.AppendLine("AvoidDiskWrites 1");
        sb.AppendLine("ClientOnly 1");
        // A shorter dirtiness window means a plain NEWNYM really does hand out a fresh exit quickly.
        sb.AppendLine("MaxCircuitDirtiness 60");
        sb.AppendLine("NewCircuitPeriod 30");

        // GeoIP files ship next to tor.exe (…/tor/tor.exe with …/data/geoip). Optional: without them
        // Tor still works, it just cannot honour country options.
        try
        {
            string? torDir = Path.GetDirectoryName(torExe);
            foreach (var candidate in new[] { torDir, torDir == null ? null : Path.Combine(torDir, "..", "data"), torDir == null ? null : Path.Combine(torDir, "data") })
            {
                if (candidate == null) continue;
                string geo = Path.GetFullPath(Path.Combine(candidate, "geoip"));
                string geo6 = Path.GetFullPath(Path.Combine(candidate, "geoip6"));
                if (File.Exists(geo)) { sb.AppendLine($"GeoIPFile {Quote(geo)}"); }
                if (File.Exists(geo6)) { sb.AppendLine($"GeoIPv6File {Quote(geo6)}"); }
                if (File.Exists(geo)) break;
            }
        }
        catch (Exception ex) { Log("Tor geoip probe failed: " + ex.Message, LogLevel.Warning); }

        return sb.ToString();
    }

    static string Quote(string p) => "\"" + p.Replace('\\', '/') + "\"";

    static void OnTorLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return;
        lock (_bootLog) { _bootLog.Add(line); if (_bootLog.Count > 60) _bootLog.RemoveAt(0); }
        if (line.Contains("Bootstrapped", StringComparison.OrdinalIgnoreCase)
            || line.Contains("[warn]", StringComparison.OrdinalIgnoreCase)
            || line.Contains("[err]", StringComparison.OrdinalIgnoreCase))
            Log("tor: " + line.Trim(), LogLevel.Info);
    }

    static string LastBootLines()
    {
        lock (_bootLog) return string.Join(" | ", _bootLog.TakeLast(6));
    }

    static async Task<bool> WaitForBootstrapAsync(CancellationToken ct)
    {
        var deadline = DateTime.UtcNow.AddSeconds(90);
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (_proc is { HasExited: true })
            {
                LastError = string.Format(Strings.TorErrExitedFormat, LastBootLines());
                return false;
            }
            lock (_bootLog)
                if (_bootLog.Any(l => l.Contains("Bootstrapped 100%", StringComparison.OrdinalIgnoreCase)))
                    return true;
            await Task.Delay(300, ct);
        }
        return false;
    }

    static int FreePort(int avoid = 0)
    {
        for (int attempt = 0; attempt < 40; attempt++)
        {
            try
            {
                var l = new TcpListener(IPAddress.Loopback, 0);
                l.Start();
                int port = ((IPEndPoint)l.LocalEndpoint).Port;
                l.Stop();
                if (port != avoid) return port;
            }
            catch (Exception ex) { Log("Free-port probe failed: " + ex.Message, LogLevel.Warning); }
        }
        // Deterministic fallback well away from Tor Browser's 9150/9151.
        return avoid == 0 ? 39050 : 39051;
    }

    // ---- circuit control ----

    /// <summary>Asks Tor for a brand-new circuit (new exit IP) over the control port. Returns false
    /// with <see cref="LastError"/> set when Tor is off or the control port refuses.</summary>
    public static async Task<bool> NewCircuitAsync(CancellationToken ct = default)
    {
        if (!IsActive) { LastError = Strings.TorErrNotRunning; Raise(); return false; }
        try
        {
            string cookie = ReadControlCookieHex();
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, _controlPort, ct);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
            using var writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };

            await writer.WriteLineAsync("AUTHENTICATE " + cookie);
            string? authReply = await reader.ReadLineAsync(ct);
            if (authReply == null || !authReply.StartsWith("250", StringComparison.Ordinal))
            {
                LastError = string.Format(Strings.TorErrControlAuthFormat, authReply ?? "-");
                Log("Tor control auth failed: " + (authReply ?? "(no reply)"), LogLevel.Warning);
                return false;
            }

            await writer.WriteLineAsync("SIGNAL NEWNYM");
            string? sigReply = await reader.ReadLineAsync(ct);
            await writer.WriteLineAsync("QUIT");

            if (sigReply == null || !sigReply.StartsWith("250", StringComparison.Ordinal))
            {
                LastError = string.Format(Strings.TorErrNewnymFormat, sigReply ?? "-");
                Log("Tor NEWNYM refused: " + (sigReply ?? "(no reply)"), LogLevel.Warning);
                return false;
            }

            CircuitCount++;
            LastError = null;
            ExitIp = null; ExitCountry = null;
            Raise();
            Log($"Tor circuit changed (#{CircuitCount}).", LogLevel.Info);

            // Tor needs a moment to build the new circuit before the exit IP is meaningful.
            await Task.Delay(2500, ct);
            await RefreshExitInfoAsync(ct);
            return true;
        }
        catch (OperationCanceledException) { return false; }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Log("Tor new-circuit failed: " + ex, LogLevel.Warning);
            Raise();
            return false;
        }
    }

    static string ReadControlCookieHex()
    {
        string cookiePath = Path.Combine(ConfigPathResolver.DataFolder, "tor-data", "control_auth_cookie");
        byte[] bytes = File.ReadAllBytes(cookiePath);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    // ---- exit-node info ----

    /// <summary>Looks up the current exit IP + country through the proxy. Best effort: two
    /// independent providers, then the Tor project's own endpoint for at least the address.</summary>
    public static async Task RefreshExitInfoAsync(CancellationToken ct = default)
    {
        if (!IsActive) return;
        try
        {
            using var http = BuildProbeClient();

            // 1) one call that carries both address and country
            try
            {
                string json = await http.GetStringAsync("http://ip-api.com/json/?fields=status,query,country,countryCode", ct);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("query", out var q) && q.GetString() is { Length: > 0 } ip)
                {
                    ExitIp = ip;
                    string? country = root.TryGetProperty("country", out var c) ? c.GetString() : null;
                    string? code = root.TryGetProperty("countryCode", out var cc) ? cc.GetString() : null;
                    ExitCountry = string.IsNullOrWhiteSpace(country) ? code
                        : string.IsNullOrWhiteSpace(code) ? country : $"{country} ({code})";
                    Raise();
                    return;
                }
            }
            catch (Exception ex) { Log("Tor exit lookup (ip-api) failed: " + ex.Message, LogLevel.Warning); }

            // 2) a TLS provider that also returns the country
            try
            {
                string json = await http.GetStringAsync("https://ipinfo.io/json", ct);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("ip", out var ipEl) && ipEl.GetString() is { Length: > 0 } ip2)
                {
                    ExitIp = ip2;
                    ExitCountry = root.TryGetProperty("country", out var c2) ? c2.GetString() : null;
                    Raise();
                    return;
                }
            }
            catch (Exception ex) { Log("Tor exit lookup (ipinfo) failed: " + ex.Message, LogLevel.Warning); }

            // 3) last resort: address only, straight from the Tor project
            try
            {
                string json = await http.GetStringAsync("https://check.torproject.org/api/ip", ct);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("IP", out var ipEl) && ipEl.GetString() is { Length: > 0 } ip3)
                {
                    ExitIp = ip3;
                    ExitCountry = null;
                    Raise();
                }
            }
            catch (Exception ex) { Log("Tor exit lookup (check.torproject.org) failed: " + ex.Message, LogLevel.Warning); }
        }
        catch (Exception ex) { Log("Tor exit info refresh failed: " + ex.Message, LogLevel.Warning); }
        finally { Raise(); }
    }

    static HttpClient BuildProbeClient()
    {
        var handler = new HttpClientHandler
        {
            Proxy = new WebProxy($"socks5://127.0.0.1:{_socksPort}"),
            UseProxy = true,
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
    }

    /// <summary>One line for the UI: "Çıkış: 185.x.x.x · Almanya (DE)" or a status word.</summary>
    public static string StatusLine()
    {
        if (IsBusy) return Strings.TorStatusStarting;
        if (!IsActive) return Strings.TorStatusOff;
        if (ExitIp == null) return Strings.TorStatusOnNoIp;
        return string.Format(Strings.TorStatusOnFormat, ExitIp, ExitCountry ?? "?");
    }

    static void Raise()
    {
        try { StateChanged?.Invoke(); }
        catch (Exception ex) { Log("Tor StateChanged handler failed: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Called from app shutdown so no orphan tor.exe is left behind.</summary>
    public static void Shutdown()
    {
        try { Disable(); } catch (Exception ex) { Log("Tor shutdown failed: " + ex.Message, LogLevel.Warning); }
    }
}
