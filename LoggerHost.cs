namespace VirusTotalScanner;

/// <summary>
/// Wires the global <see cref="Logger"/> into the app: points it at the data folder for
/// log files, mirrors the user's logging on/off setting, and forwards each line to the
/// live in-app log viewer via <see cref="OnLogLine"/>. Keeps the Logger itself UI-free.
/// </summary>
internal static class LoggerHost
{
    /// <summary>Raised for every log line produced (the in-app viewer subscribes to this).</summary>
    public static event Action<string>? OnLogLine;

    static bool _initialized;

    public static void Initialize()
    {
        if (_initialized) return;
        _initialized = true;

        Logger.LogsFolderProvider = () => ConfigPathResolver.LogsFolder;
        Logger.Sink = line => { try { OnLogLine?.Invoke(line); } catch { } };

        // Apply the persisted preference. Settings must already be loaded.
        SetEnabled(Settings.EnableLogging);
    }

    /// <summary>Turns logging on/off at runtime and persists the choice.</summary>
    public static void SetEnabled(bool enabled)
    {
        Logger.ActivateLogging = enabled;
        if (Settings.EnableLogging.Value != enabled)
        {
            Settings.EnableLogging.Value = enabled;
            SettingsManager.SaveSettings();
        }
    }

    public static bool IsEnabled => Logger.ActivateLogging;
}
