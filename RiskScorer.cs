namespace VirusTotalScanner;

/// <summary>
/// A cheap, fully-local suspicion score used to order a scan so the likeliest-malicious files get a
/// VirusTotal verdict first (the keyless engine is throttled, so order matters on big batches). Uses
/// only fast file-metadata signals — Mark-of-the-Web, location, freshness, extension class — and
/// deliberately does NOT compute the signature/hash (those happen per-item during the scan).
/// </summary>
internal static class RiskScorer
{
    static readonly HashSet<string> ScriptExts = new(StringComparer.OrdinalIgnoreCase)
    { ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".ps1", ".hta", ".wsf", ".lnk", ".jar" };

    static readonly HashSet<string> ArchiveExts = new(StringComparer.OrdinalIgnoreCase)
    { ".zip", ".7z", ".rar", ".iso", ".cab", ".gz" };

    public static int Score(string path)
    {
        int s = 0;
        try
        {
            if (ZoneIdentifier.Read(path)?.FromInternet == true) s += 40;          // downloaded from the internet

            string lower = path.ToLowerInvariant();
            if (lower.Contains(@"\downloads\") || lower.Contains(@"\temp\") ||
                lower.Contains(@"\appdata\local\temp") || lower.Contains(@"\inetcache\"))
                s += 25;                                                            // common drop locations

            try
            {
                double days = (DateTime.UtcNow - File.GetLastWriteTimeUtc(path)).TotalDays;
                if (days < 3) s += 20; else if (days < 14) s += 10;                 // fresh drop
            }
            catch { }

            string ext = Path.GetExtension(path);
            if (ScriptExts.Contains(ext)) s += 25;                                  // loader/scripting class
            else if (ArchiveExts.Contains(ext)) s += 10;
            if (HasDoubleExtension(path)) s += 30;                                  // invoice.pdf.exe
        }
        catch { }
        return s;
    }

    static bool HasDoubleExtension(string path)
    {
        string name = Path.GetFileNameWithoutExtension(path);
        string inner = Path.GetExtension(name).ToLowerInvariant();
        // A real second extension that looks like a document/media masquerade.
        return inner is ".pdf" or ".doc" or ".docx" or ".xls" or ".jpg" or ".png" or ".txt" or ".mp4" or ".zip";
    }
}
