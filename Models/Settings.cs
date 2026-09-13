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

    /// <summary>Which files get a VirusTotal lookup at all during a FOLDER sweep.
    /// 0 = every file the excluded-extension list left in (default), 1 = only code-shaped files.
    ///
    /// What a sweep covers is decided by exclusion: the extension list says what is left out, and
    /// everything else is looked up. Option 1 turns that into a whitelist instead — a dry run of one C:
    /// drive found 195,833 of 338,603 files were neither executable, script, installer, archive nor
    /// macro-capable document, and skipping those makes a sweep finish far sooner at the cost of not
    /// asking about them. It is off unless chosen. Files the user picked by hand are always looked up,
    /// whatever this says.</summary>
    public static readonly Setting<int> LookupPolicy = new(0);

    /// <summary>What to do with a file VirusTotal has never seen.
    /// 0 = never upload (hash lookups only), 1 = upload only code-shaped files (default),
    /// 2 = upload anything. A submission costs a request and the analysis after it costs more, and a
    /// disk holds tens of thousands of tiny resource payloads that can never be malware.</summary>
    public static readonly Setting<int> UploadPolicy = new(1);

    /// <summary>Use the local hash cache to avoid re-querying VirusTotal for known files.</summary>
    public static readonly Setting<bool> UseLocalHashCache = new(true);

    /// <summary>Remember path + size + write-time -> hashes, so a repeat scan does not read the whole
    /// disk again to arrive at the same digests. A file rewritten with an identical length AND an
    /// unchanged timestamp would be missed; a re-scan that bypasses trust always hashes for real.</summary>
    public static readonly Setting<bool> UseFingerprintCache = new(true);

    /// <summary>How many days a cached clean verdict stays valid. 0 = never expires (the default):
    /// VirusTotal is not an antivirus, so re-asking it about a file it already answered for only
    /// burns quota. The periodic re-check sweep is what catches a verdict that changed later.</summary>
    public static readonly Setting<int> HashCacheDays = new(0);

    /// <summary>How many days a cached malicious verdict stays valid. 0 = never expires.</summary>
    public static readonly Setting<int> ThreatCacheDays = new(0);

    /// <summary>Folder the hash cache is copied into on a timer (empty = no backups).</summary>
    public static readonly Setting<string> CacheBackupFolder = new("");

    /// <summary>Hours between hash-cache backups (0 = only when the button is pressed).</summary>
    public static readonly Setting<int> CacheBackupHours = new(24);

    /// <summary>How many timestamped cache backups to keep in the backup folder before the oldest
    /// are removed (0 = keep every one).</summary>
    public static readonly Setting<int> CacheBackupKeep = new(30);

    /// <summary>Skip files larger than this many MB before hashing (0 = no cap). VT's own upload
    /// ceiling is ~650 MB, so very large files cannot be analyzed anyway.</summary>
    public static readonly Setting<int> MaxFileSizeMB = new(0);

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

    // ---- Tor (source-IP rotation for the keyless path) ----

    /// <summary>Route VirusTotal traffic (API + keyless browser) through a private Tor process.</summary>
    public static readonly Setting<bool> UseTor = new(false);

    /// <summary>Explicit path to tor.exe. Empty = search PATH, scoop and the Tor Browser folders.</summary>
    public static readonly Setting<string> TorExePath = new("");

    /// <summary>Turn Tor on by itself after the source IP has been blocked repeatedly in one day.</summary>
    public static readonly Setting<bool> TorAutoEnable = new(true);

    /// <summary>How many IP-level blocks within 24 h switch Tor on automatically.</summary>
    public static readonly Setting<int> TorAutoEnableAfter = new(3);

    /// <summary>While Tor is carrying the traffic, take a new circuit (new exit IP) after a failure.</summary>
    public static readonly Setting<bool> TorNewCircuitOnError = new(true);

    /// <summary>Also send the API calls through Tor. Off by default: the API is authenticated by key
    /// and is not limited by source address, so a new exit buys it nothing and costs it latency and
    /// the risk of an exit VirusTotal's edge refuses. The keyless browser — which IS limited by source
    /// address — always follows Tor when it is on.</summary>
    public static readonly Setting<bool> TorRouteApi = new(false);

    /// <summary>Let the app try the reCAPTCHA's single "I am not a robot" click by itself before it
    /// interrupts the user. If a picture puzzle follows, the window is shown as usual.</summary>
    public static readonly Setting<bool> CaptchaAutoClick = new(true);

    /// <summary>How many keyless (WebView2) browsers run at once — the ceiling on concurrent keyless
    /// lookups. 0 = auto, which follows <see cref="MaxConcurrentScans"/>. The live count never exceeds
    /// the scan concurrency (there are only that many network workers), so a value above it has no
    /// effect. A change applies the next time the keyless pool is idle (a new scan).</summary>
    public static readonly Setting<int> KeylessBrowserPool = new(0);

    /// <summary>Minimize to the system tray instead of closing.</summary>
    public static readonly Setting<bool> MinimizeToTray = new(true);

    /// <summary>Show a Windows toast/notification when a threat is found.</summary>
    public static readonly Setting<bool> NotifyOnThreat = new(true);

    /// <summary>Only notify for threats with at least this many engine detections (1 = any threat).</summary>
    public static readonly Setting<int> NotifyMinDetections = new(1);

    /// <summary>Show one summary toast (clean/suspect/threat tally) when a scan finishes.</summary>
    public static readonly Setting<bool> NotifyScanSummary = new(false);

    /// <summary>Auto-quarantine high-confidence threats caught by a BACKGROUND source (download watcher,
    /// USB auto-scan) without waiting for the user to click — only when enabled below.</summary>
    public static readonly Setting<bool> AutoQuarantineWatchers = new(false);

    /// <summary>Detection count at/above which a background threat is auto-quarantined (0 = off). Set high
    /// (e.g. 10) so only obvious malware is touched; the .VIRUS vault + an undo toast cover false positives.</summary>
    public static readonly Setting<int> AutoQuarantineThreshold = new(10);

    /// <summary>ISO-8601 UTC of the most recent scheduled-sweep result already surfaced to the user, so a
    /// sweep's findings are announced once on next launch and not repeated.</summary>
    public static readonly Setting<string> LastSeenSweepUtc = new("");

    /// <summary>Quiet-hours window (local hour 0–23) during which non-urgent toasts are held back and
    /// replayed grouped afterward. Start==End disables the window.</summary>
    public static readonly Setting<int> QuietHoursStart = new(0);
    public static readonly Setting<int> QuietHoursEnd = new(0);

    /// <summary>Hold back non-urgent toasts while a fullscreen app (game/presentation) is foreground.</summary>
    public static readonly Setting<bool> MuteInFullscreen = new(true);

    /// <summary>Show VirusTotal community votes in the detail pane.</summary>
    public static readonly Setting<bool> ShowCommunityVotes = new(true);

    /// <summary>Watch download folders and auto-scan new executable-class files as they land.</summary>
    public static readonly Setting<bool> WatchDownloads = new(false);

    /// <summary>Offer to scan a removable drive (USB stick, SD card) when it is plugged in.</summary>
    public static readonly Setting<bool> WatchUsb = new(true);

    /// <summary>Scan a plugged-in removable drive immediately (background) without waiting for the user to
    /// click the toast — high-detection finds are auto-quarantined via the background threat path.</summary>
    public static readonly Setting<bool> AutoScanUsb = new(false);

    /// <summary>Real-time guard: check every newly-launched executable at start (WMI; needs admin). Catches
    /// an unknown exe double-clicked from chat/email that never touched the watched folders.</summary>
    public static readonly Setting<bool> WatchProcessLaunches = new(false);

    /// <summary>ISO-8601 UTC of the last download-watch catch-up, so files that landed while the watcher
    /// was off (app closed / WatchDownloads just toggled on) are verdicted once on next start.</summary>
    public static readonly Setting<string> LastWatchScanUtc = new("");

    /// <summary>Permanently purge quarantined files older than this many days on startup (0 = keep forever).</summary>
    public static readonly Setting<int> QuarantineRetentionDays = new(0);

    /// <summary>Re-run the watch-list re-verdict, due-cache re-check and baseline drift check every N hours
    /// while the app sits in the tray (keyless, zero quota). 0 = only on startup.</summary>
    public static readonly Setting<int> PeriodicRecheckHours = new(12);

    /// <summary>Folders watched when <see cref="WatchDownloads"/> is on (; separated; empty = Downloads + Desktop).</summary>
    public static readonly Setting<string> WatchFolders = new("");

    /// <summary>Semicolon-separated keys of the action drawers the user left open on the scan tab.</summary>
    public static readonly Setting<string> OpenDrawers = new("");

    /// <summary>The overview's setup checklist was dismissed and must stay gone across restarts.</summary>
    public static readonly Setting<bool> OnboardDismissed = new(false);

    /// <summary>Order a scan by a cheap local suspicion score so the scariest files get a verdict first.</summary>
    public static readonly Setting<bool> RiskWeightedOrdering = new(true);

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

    /// <summary>Plain-text mirror of every API key ever held, so the DPAPI vault becoming unreadable
    /// (reinstall, new Windows profile, restore onto another machine) does not lose them. Empty
    /// disables the mirror.</summary>
    public static readonly Setting<string> KeyPlaintextBackupPath =
        new(@"D:\!Muhammet\PROGRAMLAR ve Bilgisayar Dökümanları\VirusTotalScanner - API Keys.txt");

    /// <summary>User-defined verdict categories (JSON list of {MinDetections, Name, ColorHex}).</summary>
    public static readonly Setting<string> VerdictCategoriesJson = new("");

    /// <summary>Detections from engines whose signature DB is older than this many days are flagged
    /// as possibly-stale (a re-check hint). 0 disables the signal.</summary>
    public static readonly Setting<int> StaleSignatureDays = new(60);

    /// <summary>Mark a row as a likely false positive ("imzayla yumuşatıldı") when a fully-signed file gets
    /// only 1-2 purely heuristic detections and no negative reputation. Off by default; a hint + quick
    /// mark-clean shortcut only — it never lowers the verdict band or hides a real threat.</summary>
    public static readonly Setting<bool> SignatureSoftenLowDetections = new(false);

    /// <summary>Engine names considered "major" / high-reputation (; separated). Detections are
    /// split into major vs minor so a few obscure-engine hits read clearly as a likely false positive.</summary>
    public static readonly Setting<string> MajorEnginesList =
        new("Microsoft;Kaspersky;ESET-NOD32;BitDefender;GData;Avast;AVG;Sophos;Malwarebytes;McAfee;McAfeeD;Symantec;TrendMicro;Google;DrWeb;Emsisoft;F-Secure;Fortinet;Ikarus");
}
