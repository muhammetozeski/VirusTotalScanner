namespace VirusTotalScanner;

/// <summary>What a finished lookup concluded about a file. <see cref="Unknown"/> is deliberately not a
/// flavour of clean: VirusTotal returning no engine results is the shape a brand-new payload has.</summary>
internal enum VerdictClass
{
    /// <summary>A threat by the user's verdict categories.</summary>
    Malicious,
    /// <summary>Engines flagged it, but not enough to cross the threat threshold.</summary>
    Suspicious,
    /// <summary>Engines ran and none flagged it.</summary>
    Clean,
    /// <summary>No report, or a report with no engine results — nothing was actually judged.</summary>
    Unknown,
}

/// <summary>
/// The single place a report is turned into a verdict class. The scan counters and the filter chips used
/// to classify separately, so the summary line counted a file as "Temiz" while its chip called it
/// "Şüpheli", and both counted a file VirusTotal had no data on as clean.
/// </summary>
internal static class VerdictClassifier
{
    public static VerdictClass Of(VtFileReport? report)
    {
        if (report == null || report.TotalEngines == 0) return VerdictClass.Unknown;
        if (report.IsMalicious) return VerdictClass.Malicious;
        return report.DetectionCount > 0 ? VerdictClass.Suspicious : VerdictClass.Clean;
    }
}
