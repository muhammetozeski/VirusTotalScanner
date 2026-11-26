namespace VirusTotalScanner;

/// <summary>
/// Central portable path resolver following the CSharpProgram layout:
///   Root\
///     AppCache\  (disposable session state: Logs, BrowserCache, Tor, Session, Diagnostics)
///     UserCache\ (rebuildable user cache: Fingerprints.json)
///     UserData\  (irreplaceable user data grouped into Settings, Language, Verdicts, Trust, Quarantine, Backups)
///
/// Resolving a path never creates directories on disk; each writer creates its own folder on demand.
/// Falls back to %AppData%\VirusTotalScanner only when the executable folder is not writable.
/// </summary>
internal static class ConfigPathResolver
{
    static string? _rootFolder;

    /// <summary>Portable application root (exe folder or parent of AppData payload folder, else %AppData%).</summary>
    public static string RootFolder => _rootFolder ??= ResolveRootFolder();

    // ---- Top-level CSharpProgram portable folders ----
    public static string AppCacheFolder => Path.Combine(RootFolder, "AppCache");
    public static string UserDataFolder => Path.Combine(RootFolder, "UserData");
    public static string UserCacheFolder => Path.Combine(RootFolder, "UserCache");

    // ---- UserData groups (never auto-cleaned) ----
    public static string SettingsFolder => Path.Combine(UserDataFolder, "Settings");
    public static string LanguageFolder => Path.Combine(UserDataFolder, "Language");
    public static string VerdictsFolder => Path.Combine(UserDataFolder, "Verdicts");
    public static string TrustFolder => Path.Combine(UserDataFolder, "Trust");
    public static string QuarantineFolder => Path.Combine(UserDataFolder, "Quarantine");
    public static string BackupsFolder => Path.Combine(UserDataFolder, "Backups");

    // ---- AppCache groups (safe to clean) ----
    public static string LogsFolder => Path.Combine(AppCacheFolder, "Logs");
    public static string BrowserCacheFolder => Path.Combine(AppCacheFolder, "BrowserCache");
    public static string TorFolder => Path.Combine(AppCacheFolder, "Tor");
    public static string TorDataFolder => Path.Combine(TorFolder, "Data");
    public static string TorrcPath => Path.Combine(TorFolder, "torrc");
    public static string SessionFolder => Path.Combine(AppCacheFolder, "Session");
    public static string DiagnosticsFolder => Path.Combine(AppCacheFolder, "Diagnostics");

    // ---- Key file paths ----
    /// <summary>Folder holding the main config file (<c>UserData\Settings</c>).</summary>
    public static string ConfigFolder => SettingsFolder;

    /// <summary>Full path to the main configuration file.</summary>
    public static string ConfigPath => Path.Combine(SettingsFolder, AppConstants.ConfigFileName);

    /// <summary>Default durable user data root (<c>UserData</c>).</summary>
    public static string DataFolder => UserDataFolder;

    /// <summary>Permanent VirusTotal verdict ledger (formerly <c>cache.json</c>).</summary>
    public static string VerdictLedgerPath => Path.Combine(VerdictsFolder, AppConstants.VerdictLedgerFileName);

    /// <summary>Alias for <see cref="VerdictLedgerPath"/> kept for internal callers.</summary>
    public static string HashCachePath => VerdictLedgerPath;

    /// <summary>Rebuildable local file-fingerprint cache (<c>UserCache\Fingerprints.json</c>).</summary>
    public static string FingerprintsPath => Path.Combine(UserCacheFolder, "Fingerprints.json");

    static string ResolveRootFolder()
    {
        try
        {
            string exeFolder = Path.TrimEndingDirectorySeparator(AppConstants.ThisExeFolder);
            if (!string.IsNullOrEmpty(exeFolder))
            {
                string candidate = string.Equals(Path.GetFileName(exeFolder), "AppData", StringComparison.OrdinalIgnoreCase)
                    ? (Directory.GetParent(exeFolder)?.FullName ?? exeFolder)
                    : exeFolder;
                if (IsWritable(candidate))
                    return candidate;
            }
        }
        catch (Exception ex) { Log("Root folder probe failed: " + ex.Message, LogLevel.Warning); }
        return EnsureAppData();
    }

    static string EnsureAppData()
    {
        string appData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            AppConstants.AppFolderName);
        try { Directory.CreateDirectory(appData); } catch (Exception ex) { Log("AppData dir create failed: " + ex.Message, LogLevel.Warning); }
        return appData;
    }

    static bool IsWritable(string folder)
    {
        try
        {
            string probe = Path.Combine(folder, ".vtwrite_" + Guid.NewGuid().ToString("N") + ".tmp");
            File.WriteAllText(probe, "x");
            File.Delete(probe);
            return true;
        }
        catch { return false; }
    }
}
