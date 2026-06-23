namespace VirusTotalScanner;

/// <summary>
/// All globally accessible settings. Each public static readonly Setting&lt;T&gt; field is
/// auto-registered by <see cref="SettingsManager"/> (its key is the field name). Define
/// settings here only — behaviour lives in <see cref="SettingsManager"/>.
/// </summary>
internal static class Settings
{
    /// <summary>Master logging on/off. Off by default; the user controls it.</summary>
    public static readonly Setting<bool> EnableLogging = new(false);

    /// <summary>UI theme: "Dark" or "Light".</summary>
    public static readonly Setting<string> Theme = new("Dark");

    /// <summary>UI language code ("tr" or "en"). Loaded into <see cref="Strings"/> at startup.</summary>
    public static readonly Setting<string> Language = new("tr");

    /// <summary>Follow the Windows app theme instead of the fixed Theme value.</summary>
    public static readonly Setting<bool> FollowWindowsTheme = new(true);

    /// <summary>Semicolon-separated extensions treated as "safe" (hidden from the menu / skippable).</summary>
    public static readonly Setting<string> SafeExtensions =
        new(".txt;.md;.log;.csv;.png;.jpg;.jpeg;.gif;.bmp;.webp;.ico;.svg;.mp4;.mkv;.avi;.mov;.webm;.mp3;.wav;.flac;.ogg");

    /// <summary>Max files scanned concurrently (true throttle is the 4/min key limit).</summary>
    public static readonly Setting<int> MaxConcurrentScans = new(2);

    /// <summary>Max files uploaded to VirusTotal in parallel (uploads are bandwidth-heavy, so
    /// this is throttled separately from lookups).</summary>
    public static readonly Setting<int> MaxConcurrentUploads = new(2);

    /// <summary>Use the local hash cache to avoid re-querying VirusTotal for known files.</summary>
    public static readonly Setting<bool> UseLocalHashCache = new(true);

    /// <summary>How many days a cached clean verdict stays valid.</summary>
    public static readonly Setting<int> HashCacheDays = new(7);

    /// <summary>Skip files larger than this many MB before hashing (0 = no cap). VT's own upload
    /// ceiling is ~650 MB, so very large files cannot be analyzed anyway.</summary>
    public static readonly Setting<int> MaxFileSizeMB = new(0);

    /// <summary>Whether the Explorer context-menu entries have been installed.</summary>
    public static readonly Setting<bool> ContextMenuInstalled = new(false);

    /// <summary>Exclude safe extensions from the file context menu (AppliesTo query). Off by
    /// default so the verb always shows reliably; turning it on adds an AppliesTo filter.</summary>
    public static readonly Setting<bool> ContextMenuExcludeSafe = new(false);

    // ---- Trust sources (keyless, zero-quota skip filters) ----

    /// <summary>Skip VirusTotal for files with a valid trusted code signature.</summary>
    public static readonly Setting<bool> TrustSkipSigned = new(true);

    /// <summary>Only skip Microsoft-signed files (safe default). If false, any valid signature skips.</summary>
    public static readonly Setting<bool> TrustMicrosoftOnly = new(true);

    /// <summary>Extra trusted publishers (subject CN substrings), ; separated. Always honored.</summary>
    public static readonly Setting<string> TrustPublisherAllowList = new("");

    /// <summary>Optional path to a user-supplied known-good hash list (one md5/sha256 per line).</summary>
    public static readonly Setting<string> KnownGoodHashDbPath = new("");

    /// <summary>Prefer the keyless GUI (WebView2) engine for lookups; the API is the fallback.
    /// Default ON: every lookup tries the GUI first (no key, no quota), then the API with Polly.</summary>
    public static readonly Setting<bool> KeylessGuiLookup = new(true);

    /// <summary>Minimize to the system tray instead of closing.</summary>
    public static readonly Setting<bool> MinimizeToTray = new(true);

    /// <summary>Show a Windows toast/notification when a threat is found.</summary>
    public static readonly Setting<bool> NotifyOnThreat = new(true);

    /// <summary>Show VirusTotal community votes in the detail pane.</summary>
    public static readonly Setting<bool> ShowCommunityVotes = new(true);

    /// <summary>Re-check verdicts for cached files older than this many days (a clean file can be
    /// flagged later as engines catch up). The sweep is keyless (GUI), so it costs no quota.</summary>
    public static readonly Setting<int> RecheckPeriodDays = new(14);

    /// <summary>Folder configured for the scheduled sweep (Windows Scheduled Task).</summary>
    public static readonly Setting<string> SweepFolder = new("");

    /// <summary>Skip safe-extension files during scans to save quota.</summary>
    public static readonly Setting<bool> SkipSafeExtensionsOnScan = new(false);

    /// <summary>Set once the first-run wizard has completed.</summary>
    public static readonly Setting<bool> FirstRunCompleted = new(false);

    /// <summary>Start with Windows (login) minimized to the tray.</summary>
    public static readonly Setting<bool> StartWithWindows = new(false);

    /// <summary>Remember a running scan and offer to resume it on the next startup if interrupted.</summary>
    public static readonly Setting<bool> ResumeInterruptedScans = new(false);

    /// <summary>Resume an interrupted scan on startup WITHOUT asking.</summary>
    public static readonly Setting<bool> AutoResumeScans = new(false);

    /// <summary>The API-key vault: Base64(DPAPI(JSON of all keys + quota counters)).</summary>
    public static readonly Setting<string> EncryptedKeyVault = new("");

    /// <summary>User-defined verdict categories (JSON list of {MinDetections, Name, ColorHex}).</summary>
    public static readonly Setting<string> VerdictCategoriesJson = new("");

    /// <summary>Engine names considered "major" / high-reputation (; separated). Detections are
    /// split into major vs minor so a few obscure-engine hits read clearly as a likely false positive.</summary>
    public static readonly Setting<string> MajorEnginesList =
        new("Microsoft;Kaspersky;ESET-NOD32;BitDefender;GData;Avast;AVG;Sophos;Malwarebytes;McAfee;McAfeeD;Symantec;TrendMicro;Google;DrWeb;Emsisoft;F-Secure;Fortinet;Ikarus");
}
