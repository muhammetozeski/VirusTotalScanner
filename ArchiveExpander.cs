using System.Diagnostics;
using System.IO.Compression;

namespace VirusTotalScanner;

/// <summary>
/// Expands archives into their member files in a temp folder so each member can be hashed and
/// looked up individually — no upload for the lookup. ZIP-family formats use the in-box
/// <see cref="ZipFile"/>; 7z/rar/iso/msi/cab/tar/gz use the 7-Zip CLI (<c>7z</c>) when it is on PATH.
/// </summary>
internal static class ArchiveExpander
{
    static readonly HashSet<string> ZipFamily = new(StringComparer.OrdinalIgnoreCase)
    { ".zip", ".nupkg", ".jar", ".apk", ".vsix", ".whl", ".crx", ".xpi", ".epub" };

    // Formats the 7-Zip CLI can extract (7z handles msi/iso/cab too).
    static readonly HashSet<string> SevenZipFormats = new(StringComparer.OrdinalIgnoreCase)
    { ".7z", ".rar", ".iso", ".msi", ".cab", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".lzh", ".arj" };

    const long MaxEntryBytes = 200L * 1024 * 1024; // skip absurd members
    const int MaxEntries = 500;                    // bound a zip-bomb member count

    static bool? _has7z;
    static bool Has7z => _has7z ??= Probe7z();

    static bool Probe7z()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("7z") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true });
            if (p == null) return false;
            p.WaitForExit(5000);
            return true;
        }
        catch { return false; }
    }

    /// <summary>True for archives this class can actually open and extract here and now.</summary>
    public static bool IsExpandable(string path)
    {
        string ext = Path.GetExtension(path);
        return ZipFamily.Contains(ext) || (SevenZipFormats.Contains(ext) && Has7z);
    }

    /// <summary>True for any archive kind (so the UI can offer to expand / warn about unsupported).</summary>
    public static bool IsArchive(string path)
    {
        string ext = Path.GetExtension(path);
        return ZipFamily.Contains(ext) || SevenZipFormats.Contains(ext);
    }

    /// <summary>
    /// Extracts the file members of a ZIP-family archive into a fresh temp folder and returns their
    /// paths. Bounded by member count and size; directory entries and zip-slip paths are skipped.
    /// Returns an empty list (and a temp dir that may not exist) on any failure.
    /// </summary>
    public static List<string> ExpandToTemp(string archivePath, out string tempDir)
    {
        tempDir = Path.Combine(Path.GetTempPath(), "vtscan-archives",
            Path.GetFileNameWithoutExtension(archivePath) + "_" + Guid.NewGuid().ToString("N")[..8]);
        var members = new List<string>();
        try
        {
            Directory.CreateDirectory(tempDir);
            if (ZipFamily.Contains(Path.GetExtension(archivePath))) ExtractZip(archivePath, tempDir, members);
            else ExtractWith7z(archivePath, tempDir, members);
            Log($"Archive '{Path.GetFileName(archivePath)}' expanded to {members.Count} member(s).", LogLevel.Info);
        }
        catch (Exception ex) { Log($"Archive expand failed for '{archivePath}': {ex.Message}", LogLevel.Warning); }
        return members;
    }

    static void ExtractZip(string archivePath, string tempDir, List<string> members)
    {
        string root = Path.GetFullPath(tempDir);
        using var zip = ZipFile.OpenRead(archivePath);
        int n = 0;
        foreach (var entry in zip.Entries)
        {
            if (n >= MaxEntries) { Log($"Archive '{archivePath}': stopped at {MaxEntries} members.", LogLevel.Warning); break; }
            if (string.IsNullOrEmpty(entry.Name)) continue;       // directory entry
            if (entry.Length > MaxEntryBytes) { Log("Archive member too large, skipped: " + entry.FullName, LogLevel.Info); continue; }

            // Flatten the member name to avoid sub-dirs and zip-slip; prefix the index to keep names unique.
            string flat = $"{n:D3}_{entry.Name}";
            string dest = Path.Combine(tempDir, flat);
            if (!Path.GetFullPath(dest).StartsWith(root, StringComparison.OrdinalIgnoreCase)) continue;

            try { entry.ExtractToFile(dest, overwrite: true); members.Add(dest); n++; }
            catch (Exception ex) { Log($"Archive member extract failed ({entry.FullName}): {ex.Message}", LogLevel.Warning); }
        }
    }

    static void ExtractWith7z(string archivePath, string tempDir, List<string> members)
    {
        try
        {
            using var p = new Process();
            p.StartInfo.FileName = "7z";
            foreach (var a in new[] { "x", archivePath, "-o" + tempDir, "-y", "-bso0", "-bsp0" }) p.StartInfo.ArgumentList.Add(a);
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.Start();
            p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(120000);

            int n = 0;
            foreach (var f in Directory.EnumerateFiles(tempDir, "*", SearchOption.AllDirectories))
            {
                if (n >= MaxEntries) { Log($"Archive '{archivePath}': stopped at {MaxEntries} members.", LogLevel.Warning); break; }
                try { if (new FileInfo(f).Length > MaxEntryBytes) continue; } catch { }
                members.Add(f);
                n++;
            }
        }
        catch (Exception ex) { Log($"7z extract failed for '{archivePath}': {ex.Message}", LogLevel.Warning); }
    }

    /// <summary>Best-effort cleanup of a temp folder created by <see cref="ExpandToTemp"/>.</summary>
    public static void CleanupTemp(string tempDir)
    {
        try { if (!string.IsNullOrEmpty(tempDir) && Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); }
        catch (Exception ex) { Log("Archive temp cleanup failed: " + ex.Message, LogLevel.Warning); }
    }
}
