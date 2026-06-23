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

        Vault.Load();
        Cache.Load();
        KnownGoodDb.Reload();
        Rotator = new KeyRotator(Vault);
        Scheduler = new ScanScheduler(Rotator, Api, Cache);
    }

    /// <summary>Persists counters and cache on shutdown.</summary>
    public static void Shutdown()
    {
        try { Vault.Flush(); } catch { }
        try { Cache.Flush(); } catch { }
        try { GuiScrapeService.Shutdown(); } catch { }
    }
}
