namespace VirusTotalScanner;

/// <summary>
/// "Is this the kind of file worth spending an upload on?" — the question a whole-disk sweep has to
/// answer tens of thousands of times.
///
/// A hash lookup is cheap and is done for everything. Submitting a file VirusTotal has never seen is
/// not: the upload costs a request, and the analysis that follows costs more. A 2 KB
/// <c>Square71x71Logo.scale-100.png.DATA</c> from a Store package is never going to be malware, and a
/// disk holds tens of thousands of files like it. Executable code, scripts, installers, archives and
/// macro-capable documents are where a verdict can actually change what the user does.
///
/// Classification is extension-first (free) with a magic-number fallback (16 bytes), so a renamed
/// executable is still caught and a media payload with an odd extension is still left alone.
/// </summary>
internal static class FileClass
{
    static readonly HashSet<string> CodeExts = new(StringComparer.OrdinalIgnoreCase)
    {
        // native / managed code
        ".exe", ".dll", ".sys", ".com", ".scr", ".ocx", ".cpl", ".drv", ".efi", ".node", ".pyd",
        // installers and packages
        ".msi", ".msp", ".mst", ".msix", ".appx", ".apk", ".deb", ".rpm", ".dmg", ".pkg",
        // scripts and loaders
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".hta", ".jar", ".lnk", ".pif", ".reg", ".inf", ".msc", ".gadget", ".sh", ".py", ".pl", ".rb",
        // macro-capable or exploit-carrying documents
        ".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".xlt", ".xltm",
        ".ppt", ".pptm", ".pot", ".potm", ".rtf", ".pdf", ".chm", ".one",
        // containers that usually hold the above
        ".zip", ".7z", ".rar", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".gz", ".tar", ".xz", ".ace", ".arj",
    };

    static readonly HashSet<string> RunnableExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".com", ".scr", ".pif", ".cpl", ".msi", ".msp", ".msix", ".appx",
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".lnk", ".reg",
    };

    static readonly HashSet<string> LibraryExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll", ".sys", ".ocx", ".drv", ".efi", ".node", ".pyd",
    };

    /// <summary>Sort rank by extension: 0 runs when opened (exe, installers, scripts), 1 is loaded code (dll,
    /// drivers), 2 is another code-shaped file (macro documents, archives), 3 is everything else.</summary>
    public static int RunnableRank(string extension) =>
        RunnableExts.Contains(extension) ? 0
        : LibraryExts.Contains(extension) ? 1
        : CodeExts.Contains(extension) ? 2
        : 3;

    /// <summary>Extensions that are code-shaped but so numerous in system folders that a sweep would
    /// drown in them; still classified as code, kept here only for readability of the set above.</summary>
    public static bool IsCodeExtension(string path)
    {
        try { return CodeExts.Contains(Path.GetExtension(path)); }
        catch (Exception ex) { Log($"Extension read failed for '{path}': {ex.Message}", LogLevel.Warning); return false; }
    }

    /// <summary>True when the file is worth submitting to VirusTotal if it has never been seen.
    /// Extension first; otherwise the first bytes decide, so <c>update.dat</c> that is really a PE is
    /// still caught.</summary>
    public static bool IsWorthUploading(string path)
    {
        if (IsCodeExtension(path)) return true;
        try { return LooksExecutable(path); }
        catch (Exception ex) { Log($"Magic-number read failed for '{path}': {ex.Message}", LogLevel.Warning); return false; }
    }

    /// <summary>Magic-number sniff for the executable containers worth a verdict.</summary>
    public static bool LooksExecutable(string path)
    {
        Span<byte> head = stackalloc byte[16];
        int read;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            read = fs.Read(head);
        }
        catch (IOException ex) { Log($"Locked while sniffing '{path}': {ex.Message}", LogLevel.Debug); return false; }
        catch (UnauthorizedAccessException) { return false; }

        if (read < 4) return false;

        // MZ — every Windows PE (exe/dll/sys), whatever its extension.
        if (head[0] == 0x4D && head[1] == 0x5A) return true;
        // \x7fELF — Linux binaries dropped on a Windows disk still matter.
        if (head[0] == 0x7F && head[1] == 0x45 && head[2] == 0x4C && head[3] == 0x46) return true;
        // PK\x03\x04 — zip family, which covers jar/apk/docx/xlsx/odt and plain archives.
        if (head[0] == 0x50 && head[1] == 0x4B && head[2] == 0x03 && head[3] == 0x04) return true;
        // %PDF
        if (head[0] == 0x25 && head[1] == 0x50 && head[2] == 0x44 && head[3] == 0x46) return true;
        // D0 CF 11 E0 — OLE compound file: legacy .doc/.xls/.msi.
        if (read >= 8 && head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0) return true;
        // Rar!
        if (read >= 7 && head[0] == 0x52 && head[1] == 0x61 && head[2] == 0x72 && head[3] == 0x21) return true;
        // 7z\xBC\xAF
        if (read >= 6 && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF) return true;

        return false;
    }
}
