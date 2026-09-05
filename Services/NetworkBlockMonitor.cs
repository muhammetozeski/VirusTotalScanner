namespace VirusTotalScanner;

/// <summary>
/// Watches for VirusTotal answers that mean "this SOURCE IP has asked too much today" — the keyless
/// public UI returning 429/403 — and reacts the way the user asked for:
///
///   * Tor off  -> keep going as normal, and once the same block has been hit
///                 <see cref="Settings.TorAutoEnableAfter"/> times inside 24 h, turn Tor on.
///   * Tor on   -> ask Tor for a new circuit (a new exit IP), throttled so a burst of parallel
///                 failures rotates once, not fifty times.
///
/// Per-key API quota (429 on /api/v3) is NOT an IP block — a new exit IP does not give a spent key
/// its quota back — so that path reports to <see cref="KeyRotator"/> instead and never lands here.
/// </summary>
internal static class NetworkBlockMonitor
{
    static readonly object _lock = new();
    static readonly List<DateTime> _hits = [];
    static DateTime _lastRotateUtc = DateTime.MinValue;
    static bool _autoSwitchInFlight;

    /// <summary>How many IP blocks have been seen in the last 24 hours.</summary>
    public static int HitsLast24h { get { lock (_lock) { Prune(DateTime.UtcNow); return _hits.Count; } } }

    /// <summary>Raised after Tor is switched on automatically (so the UI can refresh + tell the user).</summary>
    public static event Action? TorAutoEnabled;

    /// <summary>Raised after an automatic circuit change.</summary>
    public static event Action? CircuitAutoChanged;

    /// <summary>Report one "the IP is blocked" answer. Safe to call from any thread, very often.</summary>
    public static void ReportIpBlocked(string source)
    {
        int count;
        var now = DateTime.UtcNow;
        lock (_lock)
        {
            _hits.Add(now);
            Prune(now);
            count = _hits.Count;
        }
        Log($"VirusTotal IP-level block reported by {source} ({count} in the last 24h).", LogLevel.Warning);

        if (TorService.IsActive) { RotateThrottled(); return; }
        if (!Settings.TorAutoEnable) return;
        if (count < Math.Max(1, Settings.TorAutoEnableAfter.Value)) return;

        AutoEnable(count);
    }

    /// <summary>Report a failure that happened WHILE Tor was carrying the traffic (timeout, transport
    /// error, blocked exit). Rotates the circuit — the user asked for the exit to change on error.</summary>
    public static void ReportTorPathFailure(string source)
    {
        if (!TorService.IsActive || !Settings.TorNewCircuitOnError) return;
        Log($"Failure on the Tor path ({source}); rotating the circuit.", LogLevel.Warning);
        RotateThrottled();
    }

    static void AutoEnable(int count)
    {
        lock (_lock)
        {
            if (_autoSwitchInFlight) return;
            _autoSwitchInFlight = true;
        }
        _ = Task.Run(async () =>
        {
            try
            {
                Log($"Auto-enabling Tor: {count} IP-level blocks within 24h (threshold {Settings.TorAutoEnableAfter.Value}).", LogLevel.Warning);
                UiStatusHub.Report(Strings.StatusSourceTor, Strings.TorAutoEnablingStatus, StatusSeverity.Warning);
                bool ok = await TorService.EnableAsync();
                if (ok)
                {
                    Settings.UseTor.Value = true;
                    SettingsManager.SaveSettings();
                    // Both channels have to be told, or they keep using the address that was blocked.
                    VtHttpClientFactory.Invalidate();
                    GuiScrapeService.InvalidateSession("tor auto-enabled");
                    lock (_lock) _hits.Clear(); // the counter is about the OLD address
                    UiStatusHub.Report(Strings.StatusSourceTor, TorService.StatusLine(), StatusSeverity.Info);
                    try { TorAutoEnabled?.Invoke(); } catch (Exception ex) { Log("TorAutoEnabled handler failed: " + ex.Message, LogLevel.Warning); }
                }
                else
                {
                    UiStatusHub.Report(Strings.StatusSourceTor,
                        string.Format(Strings.TorAutoEnableFailedFormat, TorService.LastError ?? "?"), StatusSeverity.Warning);
                }
            }
            catch (Exception ex) { Log("Tor auto-enable failed: " + ex, LogLevel.Error); }
            finally { lock (_lock) _autoSwitchInFlight = false; }
        });
    }

    static void RotateThrottled()
    {
        lock (_lock)
        {
            if (_autoSwitchInFlight) return;
            if (DateTime.UtcNow - _lastRotateUtc < TimeSpan.FromSeconds(20)) return;
            _lastRotateUtc = DateTime.UtcNow;
            _autoSwitchInFlight = true;
        }
        _ = Task.Run(async () =>
        {
            try
            {
                bool ok = await TorService.NewCircuitAsync();
                if (ok)
                {
                    // A new exit address needs a new browser profile: the old VirusTotal session cookie
                    // was issued to the address that just got blocked.
                    GuiScrapeService.InvalidateSession("tor circuit rotated");
                    lock (_lock) _hits.Clear(); // fresh exit address, fresh budget
                    UiStatusHub.Report(Strings.StatusSourceTor, TorService.StatusLine());
                    try { CircuitAutoChanged?.Invoke(); } catch (Exception ex) { Log("CircuitAutoChanged handler failed: " + ex.Message, LogLevel.Warning); }
                }
                else
                {
                    UiStatusHub.Report(Strings.StatusSourceTor,
                        string.Format(Strings.TorCircuitFailedFormat, TorService.LastError ?? "?"), StatusSeverity.Warning);
                }
            }
            catch (Exception ex) { Log("Automatic circuit change failed: " + ex, LogLevel.Warning); }
            finally { lock (_lock) _autoSwitchInFlight = false; }
        });
    }

    static void Prune(DateTime now)
    {
        var cutoff = now.AddHours(-24);
        _hits.RemoveAll(t => t < cutoff);
    }
}
