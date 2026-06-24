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
            return new Reco(Level.Keep, "Güvenli tutulabilir",
                $"İmzalı{(item.Publisher != null ? " (" + item.Publisher + ")" : "")} — yayıncı doğrulandı, VT atlandı.");

        var r = item.Report;
        bool downloaded = ZoneIdentifier.Read(item.FilePath)?.FromInternet == true;
        string dl = downloaded ? " ve internetten indirildi" : "";

        if (r == null || r.TotalEngines == 0)
            return new Reco(Level.Caution, "Dikkatli ol — henüz çalıştırma",
                $"VirusTotal'de bulunamadı (bilinmiyor){dl}. Bilinmeyen dosyalar daha yüksek risklidir.");

        if (r.IsMalicious)
        {
            string what = !string.IsNullOrEmpty(r.ThreatLabel) ? r.ThreatLabel
                : !string.IsNullOrEmpty(r.Family) ? r.Family : "zararlı";
            return new Reco(Level.Remove, "Şimdi kaldır",
                $"{r.DetectionCount}/{r.TotalEngines} motor '{what}' olarak işaretledi{dl}.");
        }

        if (r.DetectionCount > 0)
        {
            string why = r.MajorClean ? "yalnızca küçük/itibarsız motorlar işaretledi (olası yanlış pozitif)"
                : r.HeuristicOnly ? "tüm tespitler sezgisel/ML (imza eşleşmesi yok)"
                : $"{r.DetectionCount} motor işaretledi";
            return new Reco(Level.Caution, "Dikkatli ol — henüz çalıştırma", $"{why}{dl}.");
        }

        bool rareNew = r.FirstSeenUtc is { } first && (DateTime.UtcNow - first).TotalDays < 2;
        if (rareNew)
            return new Reco(Level.Caution, "Dikkatli ol", $"0 tespit ama çok yeni/nadir bir dosya{dl}.");
        return new Reco(Level.Keep, "Güvenli tutulabilir", $"0/{r.TotalEngines} tespit.");
    }
}
