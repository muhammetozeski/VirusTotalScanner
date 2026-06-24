using System.Reflection;
using System.Text;

namespace VirusTotalScanner;

/// <summary>
/// Registers, loads and saves all <see cref="Settings"/> fields. Adapted from
/// C:\E\KodlamaProjeleri\CSharp\TPMPass\SettingsManager.cs. The load/save path
/// inconsistency in the original is fixed here: both use
/// <see cref="ConfigPathResolver.ConfigPath"/>.
/// </summary>
internal static class SettingsManager
{
    static readonly Dictionary<string, ISettingSetup> iSettingSetups = [];
    static readonly Dictionary<string, ISetting> iSettings = [];

    public static ISetting[] GetAllSettings() => [.. iSettings.Values];

    static SettingsManager()
    {
        foreach (var field in typeof(Settings).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            object? value = field.GetValue(null);
            if (value is ISettingSetup setupSetting)
            {
                setupSetting.InitializeKey(field.Name);
                iSettingSetups.Add(field.Name, setupSetting);
                if (value is ISetting setting)
                    iSettings[field.Name] = setting;
            }
        }
    }

    /// <summary>Loads settings from the config file, creating it with defaults if missing.</summary>
    public static void LoadSettings()
    {
        string path = ConfigPathResolver.ConfigPath;
        if (!File.Exists(path))
        {
            SaveSettings();
            return;
        }

        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith(AppConstants.CommentPrefix)) continue;

            // Split on the FIRST '=' only, so Base64 padding ('==') in values survives.
            var parts = line.Split(AppConstants.KeyValueSeparator, 2);
            if (parts.Length != 2) continue;

            string key = parts[0].Trim();
            string value = parts[1].Trim();

            if (iSettingSetups.TryGetValue(key, out var setting))
                setting.LoadFromStr(value);
        }
    }

    /// <summary>Serializes all settings to the single config file.</summary>
    public static void SaveSettings()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{AppConstants.CommentPrefix} {AppConstants.AppTitle} Configuration");
        sb.AppendLine($"{AppConstants.CommentPrefix} Generated {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

        foreach (var setting in iSettingSetups.Values)
            sb.AppendLine($"{setting.Key} {AppConstants.KeyValueSeparator} {setting.Serialize()}");

        try
        {
            Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
            AtomicFile.WriteAllText(ConfigPathResolver.ConfigPath, sb.ToString());
        }
        catch (Exception ex)
        {
            Log("Failed to save settings: " + ex, LogLevel.Error);
        }
    }

    // The DPAPI-bound encrypted API-key blob: never exported/imported (it's machine-bound and sensitive).
    static readonly HashSet<string> PortableOmit = new(StringComparer.OrdinalIgnoreCase) { nameof(Settings.EncryptedKeyVault) };

    /// <summary>Reset every registered setting to its shipped default and persist.</summary>
    public static void ResetAllToDefaults()
    {
        foreach (var s in iSettings.Values) s.ResetToDefault();
        SaveSettings();
    }

    /// <summary>Write the portable config (all key=value lines except the encrypted key vault) to a file.</summary>
    public static void ExportSettings(string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{AppConstants.CommentPrefix} {AppConstants.AppTitle} settings export — {DateTime.Now:yyyy-MM-dd}");
        foreach (var setting in iSettingSetups.Values)
            if (!PortableOmit.Contains(setting.Key))
                sb.AppendLine($"{setting.Key} {AppConstants.KeyValueSeparator} {setting.Serialize()}");
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
    }

    /// <summary>Apply a previously-exported config file (skipping the encrypted vault). Returns keys applied.</summary>
    public static int ImportSettings(string path)
    {
        int n = 0;
        foreach (var line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith(AppConstants.CommentPrefix)) continue;
            var parts = line.Split(AppConstants.KeyValueSeparator, 2);
            if (parts.Length != 2) continue;
            string key = parts[0].Trim(), value = parts[1].Trim();
            if (PortableOmit.Contains(key)) continue;
            if (iSettingSetups.TryGetValue(key, out var s)) { s.LoadFromStr(value); n++; }
        }
        if (n > 0) SaveSettings();
        return n;
    }
}
