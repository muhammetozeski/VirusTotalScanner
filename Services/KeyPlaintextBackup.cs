using System.Text;
using System.Text.RegularExpressions;

namespace VirusTotalScanner;

/// <summary>
/// Keeps a plain-text copy of every API key the vault has ever held, in a file the user chose.
/// The vault itself is DPAPI-encrypted and bound to this Windows account: a reinstall, a profile
/// reset or a restore onto another machine makes it unreadable, and the keys are then gone. This
/// file is the way back. It only ever grows — a key removed from the vault stays listed — and the
/// same key is never written twice.
/// </summary>
internal static partial class KeyPlaintextBackup
{
    [GeneratedRegex("(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")]
    private static partial Regex KeyPattern();

    static readonly object _lock = new();

    /// <summary>Merges the vault's keys into the file. Returns false with a reason on failure.</summary>
    public static bool Export(IEnumerable<string> vaultKeys, out string error)
    {
        error = "";
        string path = (Settings.KeyPlaintextBackupPath.Value ?? "").Trim().Trim('"');
        if (path.Length == 0) { error = Strings.KeyBackupNoPath; return false; }

        lock (_lock)
        {
            try
            {
                var ordered = new List<string>();
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // Everything already written stays, in its original order, even if the vault dropped it.
                foreach (var old in ReadExisting(path))
                    if (seen.Add(old)) ordered.Add(old);

                int added = 0;
                foreach (var k in vaultKeys)
                {
                    string key = (k ?? "").Trim();
                    if (key.Length == 0) continue;
                    if (seen.Add(key)) { ordered.Add(key); added++; }
                }

                string? dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(path, Render(ordered, path), new UTF8Encoding(true));
                Log($"API key plain-text backup written: {ordered.Count} key(s), {added} new -> {path}", LogLevel.Info);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                Log("API key plain-text backup failed: " + ex, LogLevel.Error);
                // The point of this file is to survive a bad day, so a failure on the chosen path is
                // retried next to the exe rather than silently dropped.
                try
                {
                    string fallback = Path.Combine(ConfigPathResolver.DataFolder, "api-keys-plaintext.txt");
                    File.WriteAllText(fallback, Render(vaultKeys.Where(k => !string.IsNullOrWhiteSpace(k)).Distinct(StringComparer.OrdinalIgnoreCase).ToList(), fallback), new UTF8Encoding(true));
                    error = string.Format(Strings.KeyBackupFellBackFormat, ex.Message, fallback);
                    Log("API key backup fell back to " + fallback, LogLevel.Warning);
                    return true;
                }
                catch (Exception inner) { Log("Fallback API key backup ALSO failed: " + inner, LogLevel.Error); }
                return false;
            }
        }
    }

    /// <summary>Every 64-hex token already present in the file (that is what a VirusTotal key is).</summary>
    public static List<string> ReadExisting(string path)
    {
        var found = new List<string>();
        try
        {
            if (!File.Exists(path)) return found;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match m in KeyPattern().Matches(File.ReadAllText(path)))
                if (seen.Add(m.Value)) found.Add(m.Value.ToLowerInvariant());
        }
        catch (Exception ex) { Log($"Reading the existing key backup '{path}' failed: {ex.Message}", LogLevel.Warning); }
        return found;
    }

    static string Render(List<string> keys, string path)
    {
        var sb = new StringBuilder();
        sb.AppendLine("VirusTotalScanner - VirusTotal API anahtarlari (duz metin yedek)");
        sb.AppendLine("Bu dosyayi program otomatik gunceller. Ayni anahtar iki kez yazilmaz;");
        sb.AppendLine("daha once yazilmis anahtarlar vault'tan silinse bile burada kalir.");
        sb.AppendLine("Son guncelleme: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        sb.AppendLine("Toplam benzersiz anahtar: " + keys.Count);
        sb.AppendLine("Kaynak: " + ConfigPathResolver.ConfigPath);
        sb.AppendLine("Dosya  : " + path);
        sb.AppendLine();
        sb.AppendLine("----------------------------------------------------------------");
        for (int i = 0; i < keys.Count; i++) sb.AppendLine($"{i + 1,3}) {keys[i]}");
        sb.AppendLine("----------------------------------------------------------------");
        sb.AppendLine("Sadece anahtarlar:");
        foreach (var k in keys) sb.AppendLine(k);
        return sb.ToString();
    }
}
