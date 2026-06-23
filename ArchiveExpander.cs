using System.IO.Compression;

namespace VirusTotalScanner;

/// <summary>
/// Expands ZIP-family archives (.zip, .nupkg, .jar, .apk …) into their member files in a temp
/// folder so each member can be hashed and looked up individually — no upload for the lookup.
/// 7z/rar/msi/iso need extra libraries and are not expanded yet (reported, not extracted).
/// </summary>
internal static class ArchiveExpander
{
    static readonly HashSet<string> ZipFamily = new(StringComparer.OrdinalIgnoreCase)
    { ".zip", ".nupkg", ".jar", ".apk", ".vsix", ".whl", ".crx", ".xpi", ".epub" };

    static readonly HashSet<string> NeedsExtraTooling = new(StringComparer.OrdinalIgnoreCase)
    { ".7z", ".rar", ".msi", ".iso", ".cab", ".tar", ".gz", ".tgz", ".bz2" };

    const long MaxEntryBytes = 200L * 1024 * 1024; // skip absurd members
    const int MaxEntries = 500;                    // bound a zip-bomb member count

    /// <summary>True for archives this class can actually open and extract (ZIP family).</summary>
    public static bool IsExpandable(string path) => ZipFamily.Contains(Path.GetExtension(path));

    /// <summary>True for any archive kind (so the UI can offer to expand / warn about unsupported).</summary>
    public static bool IsArchive(string path)
    {
        string ext = Path.GetExtension(path);
        return ZipFamily.Contains(ext) || NeedsExtraTooling.Contains(ext);
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
            Log($"Archive '{Path.GetFileName(archivePath)}' expanded to {members.Count} member(s).", LogLevel.Info);
        }
        catch (Exception ex) { Log($"Archive expand failed for '{archivePath}': {ex.Message}", LogLevel.Warning); }
        return members;
    }

    /// <summary>Best-effort cleanup of a temp folder created by <see cref="ExpandToTemp"/>.</summary>
    public static void CleanupTemp(string tempDir)
    {
        try { if (!string.IsNullOrEmpty(tempDir) && Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); }
        catch (Exception ex) { Log("Archive temp cleanup failed: " + ex.Message, LogLevel.Warning); }
    }
}
