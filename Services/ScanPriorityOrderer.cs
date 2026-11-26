namespace VirusTotalScanner;

/// <summary>
/// Deterministic, zero-I/O primary scan priority orderer enforcing the strict extension hierarchy:
///   .exe > .dll > .bat (> .cmd) > .ps1 (> .psm1/.psd1) > .lnk > other executables/scripts > archives/macro docs > other.
///
/// Works at any scale (even 300,000+ files in tens of milliseconds) because tier classification inspects
/// only the filename extension. Within the same tier, optional local risk signals (Mark-of-the-Web,
/// Downloads/Temp path, freshness, double-extension) break ties for small/medium scans without ever
/// allowing a lower-tier extension (e.g. .lnk or .zip) to jump ahead of a higher-tier one (.exe/.dll).
/// </summary>
internal static class ScanPriorityOrderer
{
    const int RiskTieBreakCap = 5000;

    static readonly HashSet<string> OtherExecExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".com", ".scr", ".pif", ".cpl", ".msi", ".msp", ".mst", ".msix", ".appx",
        ".vbs", ".vbe", ".js", ".jse", ".mjs", ".cjs", ".wsf", ".wsh", ".hta",
        ".jar", ".sys", ".ocx", ".drv", ".efi", ".node", ".pyd",
        ".reg", ".inf", ".msc", ".gadget", ".sh", ".py", ".pl", ".rb", ".apk",
    };

    static readonly HashSet<string> ArchiveAndMacroExts = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".cab", ".iso", ".img", ".vhd", ".vhdx", ".gz", ".tar", ".xz", ".ace", ".arj",
        ".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".xlt", ".xltm",
        ".ppt", ".pptm", ".pot", ".potm", ".rtf", ".pdf", ".chm", ".one",
    };

    /// <summary>Lower value = higher scan priority. Strict order: exe (0) &lt; dll (1) &lt; bat (2) &lt; cmd (3)
    /// &lt; ps1 (4) &lt; psm1/psd1 (5) &lt; lnk (6) &lt; other exec/scripts (7) &lt; archives/docs (8) &lt; other (9).</summary>
    public static int TierOfPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) return 9;
        string ext;
        try { ext = Path.GetExtension(path); }
        catch { return 9; }
        return TierOfExtension(ext);
    }

    public static int TierOfExtension(string? ext)
    {
        if (string.IsNullOrEmpty(ext)) return 9;
        if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)) return 0;
        if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)) return 1;
        if (ext.Equals(".bat", StringComparison.OrdinalIgnoreCase)) return 2;
        if (ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase)) return 3;
        if (ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase)) return 4;
        if (ext.Equals(".psm1", StringComparison.OrdinalIgnoreCase) || ext.Equals(".psd1", StringComparison.OrdinalIgnoreCase)) return 5;
        if (ext.Equals(".lnk", StringComparison.OrdinalIgnoreCase)) return 6;
        if (OtherExecExts.Contains(ext)) return 7;
        if (ArchiveAndMacroExts.Contains(ext)) return 8;
        return 9;
    }

    /// <summary>Orders file paths by strict extension tier first, then (when enabled and within the
    /// fast tie-break cap) by local risk score descending inside each tier.</summary>
    public static List<string> OrderPaths(List<string> files, bool useRiskTieBreak)
    {
        if (files.Count <= 1) return files;
        bool scoreRisk = useRiskTieBreak && files.Count <= RiskTieBreakCap;
        var keyed = new (int Tier, int NegRisk, int Index, string Path)[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            string f = files[i];
            int tier = TierOfPath(f);
            int risk = scoreRisk ? RiskScorer.Score(f) : 0;
            keyed[i] = (tier, -risk, i, f);
        }
        Array.Sort(keyed, static (a, b) =>
        {
            int c = a.Tier.CompareTo(b.Tier);
            if (c != 0) return c;
            c = a.NegRisk.CompareTo(b.NegRisk);
            return c != 0 ? c : a.Index.CompareTo(b.Index);
        });
        var result = new List<string>(keyed.Length);
        for (int i = 0; i < keyed.Length; i++) result.Add(keyed[i].Path);
        return result;
    }

    /// <summary>Compares two scan items for queue scheduling:
    ///   1) Urgent/priority-boosted items always come first (most recently promoted first).
    ///   2) Strict extension tier (exe > dll > bat > ps1 > lnk > ...).
    ///   3) Earlier AddedSequence first (FIFO inside the same tier).</summary>
    public static int CompareItems(ScanItem a, ScanItem b)
    {
        long ua = a.UrgentOrder, ub = b.UrgentOrder;
        if (ua != ub) return ub.CompareTo(ua); // higher UrgentOrder = higher priority (top of queue)
        int ta = a.PriorityTier, tb = b.PriorityTier;
        if (ta != tb) return ta.CompareTo(tb);
        return a.AddedSequence.CompareTo(b.AddedSequence);
    }

    /// <summary>Produces a comparable tuple key for .NET PriorityQueue (lower tuple = dequeued first).</summary>
    public static (long NegUrgent, int Tier, long Seq) QueueKey(ScanItem item) =>
        (-item.UrgentOrder, item.PriorityTier, item.AddedSequence);
}
