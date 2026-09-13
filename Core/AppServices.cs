namespace VirusTotalScanner;

/// <summary>
/// Composition root: builds and holds the shared services (key vault, rotator, API client,
/// hash cache, scan scheduler). Settings must be loaded before calling Initialize.
/// </summary>
internal static class AppServices
{
    public static KeyVault Vault { get; } = new();
    public static VtApiClient Api { get; } = new();
    public static HashCache Cache { get; } = new();
    public static KeyRotator Rotator { get; private set; } = null!;
    public static ScanScheduler Scheduler { get; private set; } = null!;

    static bool _initialized;

    public static void Initialize()
    {
        if (_initialized) return;
        _initialized = true;

        LocManager.Init();
        VerdictCategories.Load();
        MajorEngines.Load();
        ProductSignerRegistry.Load();
        ConfirmGateManager.Load();
        Vault.Load();
        // A key the program disabled by itself gets another chance once the cool-off has passed.
        Vault.ReArmStaleDisables();
        // Mirror the keys out on every start, not only when one is added: a vault restored from a
        // config backup would otherwise never reach the plain-text safety net.
        Vault.ExportPlaintext();
        Cache.Load();
        FingerprintCache.Load();
        KnownGoodDb.Reload();
        Rotator = new KeyRotator(Vault);
        Scheduler = new ScanScheduler(Rotator, Api, Cache);
    }

    /// <summary>Persists counters and cache on shutdown.</summary>
    public static void Shutdown()
    {
        try { Vault.Flush(); } catch (Exception ex) { Log("Vault flush failed: " + ex.Message, LogLevel.Warning); }
        try { Cache.Flush(); } catch (Exception ex) { Log("Cache flush failed: " + ex.Message, LogLevel.Warning); }
        try { FingerprintCache.Flush(); } catch (Exception ex) { Log("Fingerprint cache flush failed: " + ex.Message, LogLevel.Warning); }
        try { PendingOutbox.Flush(); } catch (Exception ex) { Log("Pending outbox flush failed: " + ex.Message, LogLevel.Warning); }
        try { GuiScrapeService.Shutdown(); } catch (Exception ex) { Log("WebView2 shutdown failed: " + ex.Message, LogLevel.Warning); }
        try { TorService.Shutdown(); } catch (Exception ex) { Log("Tor shutdown failed: " + ex.Message, LogLevel.Warning); }
    }
}
