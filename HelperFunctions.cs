using System.Diagnostics;

// Adapted from C:\E\KodlamaProjeleri\CSharp\TPMPass\HelperFunctions.cs.
// Lives in the GLOBAL namespace so "global using static HelperFunctions;" exposes these
// everywhere. Trimmed to what this app needs.
#pragma warning disable CA1050 // Declare types in namespaces
internal static class HelperFunctions
#pragma warning restore CA1050
{
    /// <summary>Inserts spaces before capitals/numbers: "AutoCopyToClipboard" -> "Auto Copy To Clipboard".</summary>
    public static string SplitCamelCase(string input) =>
        System.Text.RegularExpressions.Regex.Replace(input, "([A-Z0-9])", " $1").Trim();

    /// <summary>Human-readable byte size.</summary>
    public static string FormatBytes(long bytes)
    {
        const long KB = 1024, MB = KB * 1024, GB = MB * 1024, TB = GB * 1024;
        if (bytes < KB) return $"{bytes} B";
        if (bytes < MB) return $"{(double)bytes / KB:F2} KB";
        if (bytes < GB) return $"{(double)bytes / MB:F2} MB";
        if (bytes < TB) return $"{(double)bytes / GB:F2} GB";
        return $"{(double)bytes / TB:F2} TB";
    }

    public static long CalculateDownloadSpeed(long bytes, long ms) => ms == 0 ? 0 : (bytes * 1000) / ms;

    /// <summary>Opens a URL in the default browser.</summary>
    public static void OpenUrlInBrowser(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { Log("Could not open browser: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Opens a file/folder with the default program / Explorer.</summary>
    public static void OpenWithDefaultProgram(string path)
    {
        try
        {
            using var p = new Process();
            p.StartInfo.FileName = "explorer";
            p.StartInfo.Arguments = "\"" + path + "\"";
            p.Start();
        }
        catch (Exception ex) { Log("Could not open path: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Selects a file in Explorer.</summary>
    public static void RevealInExplorer(string path)
    {
        try { Process.Start("explorer.exe", $"/select,\"{path}\""); }
        catch (Exception ex) { Log("Could not reveal in Explorer: " + ex.Message, LogLevel.Warning); }
    }

    /// <summary>Shortens a long path with an ellipsis in the middle for display.</summary>
    public static string TruncateMiddle(string text, int max)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max) return text;
        int keep = (max - 1) / 2;
        return text[..keep] + "…" + text[^keep..];
    }

    public static void DeleteOldestFiles(string folderPath, int filesToKeep, string prefix = "")
    {
        if (!Directory.Exists(folderPath)) return;

        var datedFiles = new List<(string Path, DateTime Date)>();
        foreach (var p in Directory.GetFiles(folderPath))
        {
            string name = Path.GetFileNameWithoutExtension(p);
            name = name.Contains(prefix) ? name.Remove(name.IndexOf(prefix), prefix.Length) : name;
            name = name.Trim();
            if (DateTime.TryParseExact(name, "yyyy.MM.dd HH.mm.ss.ff",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out DateTime d))
                datedFiles.Add((p, d));
        }

        var sorted = datedFiles.OrderBy(f => f.Date).ToList();
        for (int i = 0; i < sorted.Count - filesToKeep; i++)
        {
            try { File.Delete(sorted[i].Path); } catch { }
        }
    }
}
