namespace VirusTotalScanner;

/// <summary>
/// Synthesizes the signals the app already has (verdict + count, family/threat-label, major/minor
/// consensus, signature-vs-heuristic, trust, download origin, rarity) into ONE plain recommendation
/// for a non-expert — "keep", "be cautious", or "remove" — plus a single rationale sentence citing
/// the strongest signal. Deterministic rules over in-memory data; no new lookups, no quota.
/// </summary>
internal static class RecommendationService
{
    public enum Level { Keep, Caution, Remove }

    public sealed record Reco(Level Level, string Headline, string Rationale)
    {
        public string Emoji => Level switch { Level.Remove => "⛔", Level.Caution => "⚠", _ => "✅" };
    }

    public static Reco Build(ScanItem item)
    {
        if (item.Status == ScanStatus.TrustedSkipped)
            return new Reco(Level.Keep, Strings.RecoHeadlineKeep,
                string.Format(Strings.RecoTrustedFormat, item.Publisher != null ? " (" + item.Publisher + ")" : ""));

        var r = item.Report;
        bool downloaded = ZoneIdentifier.Read(item.FilePath)?.FromInternet == true;
        string dl = downloaded ? Strings.RecoDownloadedSuffix : "";

        if (r == null || r.TotalEngines == 0)
            return new Reco(Level.Caution, Strings.RecoHeadlineCautionDontRun,
                string.Format(Strings.RecoUnknownFormat, dl));

        if (r.IsMalicious)
        {
            string what = !string.IsNullOrEmpty(r.ThreatLabel) ? r.ThreatLabel
                : !string.IsNullOrEmpty(r.Family) ? r.Family : Strings.RecoMalwareWord;
            return new Reco(Level.Remove, Strings.RecoHeadlineRemove,
                string.Format(Strings.RecoMaliciousFormat, r.DetectionCount, r.TotalEngines, what, dl));
        }

        if (r.DetectionCount > 0)
        {
            string why = r.MajorClean ? Strings.RecoMajorClean
                : r.HeuristicOnly ? Strings.RecoHeuristicOnly
                : string.Format(Strings.RecoSomeFlaggedFormat, r.DetectionCount);
            if (Settings.ShowCommunityVotes && r.CommunityHarmlessLean)
                why += " · " + string.Format(Strings.RecoCommunityHarmlessFormat, r.VotesHarmless, r.VotesHarmless + r.VotesMalicious);
            return new Reco(Level.Caution, Strings.RecoHeadlineCautionDontRun, string.Format(Strings.RecoCautionRationaleFormat, why, dl));
        }

        bool rareNew = r.FirstSeenUtc is { } first && (DateTime.UtcNow - first).TotalDays < 2;
        if (rareNew)
            return new Reco(Level.Caution, Strings.RecoHeadlineCaution, string.Format(Strings.RecoRareNewFormat, dl));
        return new Reco(Level.Keep, Strings.RecoHeadlineKeep, string.Format(Strings.RecoCleanFormat, r.TotalEngines));
    }
}
