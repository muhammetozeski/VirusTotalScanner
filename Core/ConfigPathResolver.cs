namespace VirusTotalScanner;

/// <summary>
/// Resolves where the single config file lives and where auxiliary data (logs, hash
/// cache, quarantine) goes.
///
/// The config file is kept next to the exe when that folder is writable (portable:
/// "one exe + its config file"), otherwise it falls back to %AppData%. Logs / cache /
/// quarantine always live under %AppData%\VirusTotalScanner so the exe's own folder
/// stays clean (just the exe and its config).
/// </summary>
internal static class ConfigPathResolver
{
    static string? _configFolder;
    static string? _configPath;
    static string? _dataFolder;

    /// <summary>Folder that holds the config file (exe folder if writable, else %AppData%).</summary>
    public static string ConfigFolder => _configFolder ??= ResolveConfigFolder();

    /// <summary>Full path to the single config file.</summary>
    public static string ConfigPath => _configPath ??= Path.Combine(ConfigFolder, AppConstants.ConfigFileName);

    /// <summary>Everything (logs, cache, quarantine, webview2) lives next to the exe; falls
    /// back to %AppData% only if the exe's folder is not writable.</summary>
    public static string DataFolder => _dataFolder ??= ConfigFolder;

    public static string LogsFolder => Path.Combine(DataFolder, "Logs");
    /// <summary>Scan result cache — kept next to the exe, name "cache.json".</summary>
    public static string HashCachePath => Path.Combine(ConfigFolder, "cache.json");
    public static string QuarantineFolder => Path.Combine(DataFolder, "Quarantine");

    static string ResolveConfigFolder()
    {
        try
        {
            string exeFolder = AppConstants.ThisExeFolder;
            if (!string.IsNullOrEmpty(exeFolder) && IsWritable(exeFolder))
                return exeFolder;
        }
        catch (Exception ex) { Log("Config folder probe failed: " + ex.Message, LogLevel.Warning); }
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
