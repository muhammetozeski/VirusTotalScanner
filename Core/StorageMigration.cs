namespace VirusTotalScanner;

/// <summary>
/// Non-destructive one-time migration from the legacy flat exe-root layout to the CSharpProgram
/// portable hierarchy (<c>UserData\</c>, <c>UserCache\</c>, <c>AppCache\</c>).
///
/// Rules:
///   - Never overwrites an already-present target file (preserves newer data on partial runs).
///   - Never deletes user data on failure; falls back to copy-without-delete if a move fails.
///   - Runs before <see cref="SettingsManager.LoadSettings"/> so settings, keys, quarantine,
///     and <c>VerdictLedger.json</c> (formerly <c>cache.json</c>) load seamlessly on upgrade.
/// </summary>
internal static class StorageMigration
{
    static int _ran;

    public static void MigrateLegacyLayoutIfNeeded()
    {
        if (Interlocked.Exchange(ref _ran, 1) == 1) return;

        try
        {
            string root = ConfigPathResolver.RootFolder;
            if (!Directory.Exists(root)) return;

            // UserData\Settings
            MoveFileIfNeeded(Path.Combine(root, AppConstants.ConfigFileName), ConfigPathResolver.ConfigPath);
            MoveFileIfNeeded(Path.Combine(root, "confirm-gates.json"), Path.Combine(ConfigPathResolver.SettingsFolder, "ConfirmGates.json"));
            MoveFileIfNeeded(Path.Combine(root, "banner-mutes.json"), Path.Combine(ConfigPathResolver.SettingsFolder, "BannerMutes.json"));
            MoveFileIfNeeded(Path.Combine(root, "scan-profiles.json"), Path.Combine(ConfigPathResolver.SettingsFolder, "ScanProfiles.json"));
            MoveFileIfNeeded(Path.Combine(root, "auto-actions.json"), Path.Combine(ConfigPathResolver.SettingsFolder, "AutoActions.json"));

            // UserData\Language
            foreach (string langFile in Directory.GetFiles(root, "lang.*.xml"))
                MoveFileIfNeeded(langFile, Path.Combine(ConfigPathResolver.LanguageFolder, Path.GetFileName(langFile)));

            // UserData\Verdicts (including cache.json -> VerdictLedger.json)
            MoveFileIfNeeded(Path.Combine(root, "cache.json"), ConfigPathResolver.VerdictLedgerPath);
            MoveFileIfNeeded(Path.Combine(root, "history.json"), Path.Combine(ConfigPathResolver.VerdictsFolder, "ScanHistory.json"));
            MoveFileIfNeeded(Path.Combine(root, "behaviour-digest.json"), Path.Combine(ConfigPathResolver.VerdictsFolder, "BehaviourDigest.json"));
            MoveFileIfNeeded(Path.Combine(root, "ioc-index.json"), Path.Combine(ConfigPathResolver.VerdictsFolder, "IocIndex.json"));
            MoveFileIfNeeded(Path.Combine(root, "pending.json"), Path.Combine(ConfigPathResolver.VerdictsFolder, "PendingOutbox.json"));
            MoveFileIfNeeded(Path.Combine(root, "watch.json"), Path.Combine(ConfigPathResolver.VerdictsFolder, "ReverdictWatch.json"));
            MoveFileIfNeeded(Path.Combine(root, "escalations.json"), Path.Combine(ConfigPathResolver.VerdictsFolder, "Escalations.json"));
            MoveFileIfNeeded(Path.Combine(root, "sweep-result.json"), Path.Combine(ConfigPathResolver.VerdictsFolder, "SweepResult.json"));
            MoveFileIfNeeded(Path.Combine(root, "sweep-report.html"), Path.Combine(ConfigPathResolver.VerdictsFolder, "SweepReport.html"));

            // UserData\Trust
            MoveFileIfNeeded(Path.Combine(root, "allowlist.json"), Path.Combine(ConfigPathResolver.TrustFolder, "Allowlist.json"));
            MoveFileIfNeeded(Path.Combine(root, "folder-allowlist.json"), Path.Combine(ConfigPathResolver.TrustFolder, "FolderAllowlist.json"));
            MoveFileIfNeeded(Path.Combine(root, "baseline.json"), Path.Combine(ConfigPathResolver.TrustFolder, "Baseline.json"));
            MoveFileIfNeeded(Path.Combine(root, "product-signers.json"), Path.Combine(ConfigPathResolver.TrustFolder, "ProductSigners.json"));

            // UserData\Quarantine & Backups
            MoveDirectoryIfNeeded(Path.Combine(root, "Quarantine"), ConfigPathResolver.QuarantineFolder);
            MoveDirectoryIfNeeded(Path.Combine(root, "cache-backups"), Path.Combine(ConfigPathResolver.BackupsFolder, "VerdictLedger"));

            // UserCache
            MoveFileIfNeeded(Path.Combine(root, "fingerprints.json"), ConfigPathResolver.FingerprintsPath);

            // AppCache
            MoveDirectoryIfNeeded(Path.Combine(root, "Logs"), ConfigPathResolver.LogsFolder);
            MoveDirectoryIfNeeded(Path.Combine(root, "BrowserCache"), ConfigPathResolver.BrowserCacheFolder);
            MoveDirectoryIfNeeded(Path.Combine(root, "tor-data"), ConfigPathResolver.TorDataFolder);
            MoveFileIfNeeded(Path.Combine(root, "torrc"), ConfigPathResolver.TorrcPath);
            MoveFileIfNeeded(Path.Combine(root, "scan-session.json"), Path.Combine(ConfigPathResolver.SessionFolder, "ScanSession.json"));
        }
        catch (Exception ex)
        {
            Log("Legacy storage migration encountered an error: " + ex.Message, LogLevel.Warning);
        }
    }

    static void MoveFileIfNeeded(string source, string destination)
    {
        if (!File.Exists(source) || File.Exists(destination)) return;
        try
        {
            string? dir = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.Move(source, destination);
        }
        catch
        {
            try
            {
                string? dir = Path.GetDirectoryName(destination);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.Copy(source, destination, overwrite: false);
            }
            catch { }
        }
    }

    static void MoveDirectoryIfNeeded(string source, string destination)
    {
        if (!Directory.Exists(source) || Directory.Exists(destination)) return;
        try
        {
            string? parent = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            Directory.Move(source, destination);
        }
        catch { }
    }
}
