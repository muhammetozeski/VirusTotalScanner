using System.Net;
using System.Text;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>
/// Renders a finished scan to a report file. The format is chosen from the path's extension:
/// <c>.html/.htm</c> → a styled standalone page, <c>.json</c> → machine-readable, anything else →
/// plain text. Shared by the CLI (<c>--report</c>) and the GUI's "export report" action.
/// </summary>
internal static class ReportWriter
{
    public static void Write(string path, IReadOnlyList<ScanItem> items)
    {
        string ext = Path.GetExtension(path).ToLowerInvariant();
        string content = ext switch
        {
            ".html" or ".htm" => BuildHtml(items),
            ".json" => BuildJson(items),
            ".csv" => BuildCsv(items),
            _ => BuildText(items),
        };
        File.WriteAllText(path, content, new UTF8Encoding(false));
    }

    static (int total, int threats, int trusted, int failed) Tally(IReadOnlyList<ScanItem> items) =>
    (
        items.Count,
        items.Count(i => i.Report?.IsMalicious == true),
        items.Count(i => i.Status == ScanStatus.TrustedSkipped),
        items.Count(i => i.Status == ScanStatus.Failed)
    );

    static string BuildCsv(IReadOnlyList<ScanItem> items)
    {
        var sb = new StringBuilder();
        sb.AppendLine("File,Verdict,Malicious,Suspicious,Total,Family,MD5,SHA256,ReportUrl");
        foreach (var i in items)
        {
            var r = i.Report;
            string verdict = i.Status == ScanStatus.TrustedSkipped ? "SIGNED" : r?.Verdict ?? i.Status.ToString();
            sb.Append(Csv(i.FilePath)).Append(',')
              .Append(Csv(verdict)).Append(',')
              .Append(r?.Malicious ?? 0).Append(',')
              .Append(r?.Suspicious ?? 0).Append(',')
              .Append(r?.TotalEngines ?? 0).Append(',')
              .Append(Csv(r?.Family ?? "")).Append(',')
              .Append(Csv(i.Md5 ?? "")).Append(',')
              .Append(Csv(i.Sha256 ?? "")).Append(',')
              .Append(Csv(r?.ReportUrl ?? "")).AppendLine();
        }
        return sb.ToString();
    }

    /// <summary>Quotes a CSV field when it contains a comma, quote, or newline.</summary>
    static string Csv(string s) =>
        s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;

    static string BuildText(IReadOnlyList<ScanItem> items)
    {
        var (total, threats, trusted, failed) = Tally(items);
        var sb = new StringBuilder();
        sb.AppendLine($"{AppConstants.AppTitle} v{AppConstants.Version} — scan report");
        sb.AppendLine($"Files: {total}   Threats: {threats}   Trusted-skipped: {trusted}   Failed: {failed}");
        sb.AppendLine(new string('-', 60));
        foreach (var i in items)
        {
            var r = i.Report;
            string verdict = i.Status == ScanStatus.TrustedSkipped ? "SIGNED" : r?.Verdict ?? i.Status.ToString();
            string ratio = r != null ? $" ({r.DetectionCount}/{r.TotalEngines})" : "";
            sb.AppendLine($"[{verdict}]{ratio}  {i.FilePath}");
            if (r?.ConsensusText != null) sb.AppendLine("    " + r.ConsensusText);
            if (i.Error != null) sb.AppendLine("    error: " + i.Error);
        }
        return sb.ToString();
    }

    static string BuildJson(IReadOnlyList<ScanItem> items)
    {
        var (total, threats, trusted, failed) = Tally(items);
        var payload = new
        {
            tool = AppConstants.AppTitle,
            version = AppConstants.Version,
            summary = new { total, threats, trusted, failed },
            items = items.Select(i => new
            {
                file = i.FilePath,
                status = i.Status.ToString(),
                verdict = i.Report?.Verdict,
                malicious = i.Report?.Malicious ?? 0,
                suspicious = i.Report?.Suspicious ?? 0,
                total = i.Report?.TotalEngines ?? 0,
                majorFlaggers = i.Report?.MajorFlaggers,
                md5 = i.Md5,
                sha256 = i.Sha256,
                report = i.Report?.ReportUrl,
                detections = i.Report?.Detections.Select(d => new { engine = d.EngineName, result = d.Result }).ToArray(),
                error = i.Error,
            }),
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    static string BuildHtml(IReadOnlyList<ScanItem> items)
    {
        var (total, threats, trusted, failed) = Tally(items);
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.AppendLine($"<title>{H(AppConstants.AppTitle)} report</title>");
        sb.AppendLine("""
        <style>
          body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#e0e0e0;margin:24px}
          h1{font-size:20px;margin:0 0 4px}
          .sum{color:#9aa;margin-bottom:16px}
          table{border-collapse:collapse;width:100%}
          th,td{padding:6px 10px;border-bottom:1px solid #333;text-align:left;font-size:13px;vertical-align:top}
          th{color:#9aa;font-weight:600}
          .v{font-weight:700;white-space:nowrap}
          .threat{color:#ff6b6b}.clean{color:#6bd06b}.susp{color:#e0c060}.signed{color:#5ad}.other{color:#aaa}
          tr:hover{background:#262626}
          a{color:#5ad}
          .small{color:#888;font-size:12px}
        </style></head><body>
        """);
        sb.AppendLine($"<h1>{H(AppConstants.AppTitle)} — scan report</h1>");
        sb.AppendLine($"<div class=\"sum\">Files: {total} &nbsp; Threats: <b class=\"threat\">{threats}</b> &nbsp; Trusted-skipped: {trusted} &nbsp; Failed: {failed}</div>");
        sb.AppendLine("<table><thead><tr><th>Verdict</th><th>Detections</th><th>File</th><th>Consensus / detail</th></tr></thead><tbody>");
        foreach (var i in items)
        {
            var r = i.Report;
            bool signed = i.Status == ScanStatus.TrustedSkipped;
            string verdict = signed ? "SIGNED" : r?.Verdict ?? i.Status.ToString();
            string cls = signed ? "signed"
                : r == null ? "other"
                : r.IsMalicious ? "threat"
                : r.DetectionCount > 0 ? "susp"
                : "clean";
            string ratio = r != null ? $"{r.DetectionCount}/{r.TotalEngines}" : "";
            string detail = signed ? H(i.SkipReason ?? "trusted signature")
                : i.Error != null ? H(i.Error)
                : H(r?.ConsensusText ?? "");
            string fileCell = r != null
                ? $"<a href=\"{H(r.ReportUrl)}\">{H(i.FilePath)}</a>"
                : H(i.FilePath);
            sb.AppendLine($"<tr><td class=\"v {cls}\">{H(verdict)}</td><td>{ratio}</td><td>{fileCell}</td><td class=\"small\">{detail}</td></tr>");
        }
        sb.AppendLine("</tbody></table></body></html>");
        return sb.ToString();
    }

    static string H(string s) => WebUtility.HtmlEncode(s);

    // ---- history report (over the persisted scan log, not a live queue) ----

    /// <summary>Render the persisted scan history (optionally a date-range slice) to a standalone file —
    /// the "what did this machine see in March" document the live-queue report can't produce.</summary>
    public static void WriteHistory(string path, IEnumerable<HistoryEntry> entries, string rangeLabel)
    {
        var list = entries.OrderByDescending(e => e.WhenUtc).ToList();
        string ext = Path.GetExtension(path).ToLowerInvariant();
        string content = ext switch
        {
            ".json" => BuildHistoryJson(list, rangeLabel),
            ".csv" => BuildHistoryCsv(list),
            _ => BuildHistoryHtml(list, rangeLabel),
        };
        File.WriteAllText(path, content, new UTF8Encoding(false));
    }

    static string VtUrl(HistoryEntry e) => !string.IsNullOrEmpty(e.Sha256) ? "https://www.virustotal.com/gui/file/" + e.Sha256 : "";

    static string BuildHistoryCsv(List<HistoryEntry> list)
    {
        var sb = new StringBuilder();
        sb.AppendLine("When,File,Verdict,Detections,Total,Source,MD5,SHA256,ReportUrl");
        foreach (var e in list)
            sb.Append(Csv(e.WhenLocal.ToString("yyyy-MM-dd HH:mm"))).Append(',')
              .Append(Csv(e.Name)).Append(',').Append(Csv(e.Verdict)).Append(',')
              .Append(e.Detections).Append(',').Append(e.Total).Append(',')
              .Append(Csv(e.Source)).Append(',').Append(Csv(e.Md5 ?? "")).Append(',')
              .Append(Csv(e.Sha256 ?? "")).Append(',').Append(Csv(VtUrl(e))).AppendLine();
        return sb.ToString();
    }

    static string BuildHistoryJson(List<HistoryEntry> list, string rangeLabel)
    {
        int threats = list.Count(e => VerdictCategories.IsThreat(e.Detections));
        var payload = new
        {
            tool = AppConstants.AppTitle,
            range = rangeLabel,
            summary = new { total = list.Count, threats, clean = list.Count(e => e.Detections == 0) },
            sources = list.GroupBy(e => string.IsNullOrEmpty(e.Source) ? "—" : e.Source).ToDictionary(g => g.Key, g => g.Count()),
            entries = list.Select(e => new { when = e.WhenLocal, file = e.Name, path = e.Path, verdict = e.Verdict, detections = e.Detections, total = e.Total, source = e.Source, md5 = e.Md5, sha256 = e.Sha256, report = VtUrl(e) }),
        };
        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    static string BuildHistoryHtml(List<HistoryEntry> list, string rangeLabel)
    {
        int threats = list.Count(e => VerdictCategories.IsThreat(e.Detections));
        int clean = list.Count(e => e.Detections == 0);
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html><html lang=\"tr\"><head><meta charset=\"utf-8\">");
        sb.AppendLine($"<title>{H(AppConstants.AppTitle)} — güvenlik raporu</title>");
        sb.AppendLine("""
        <style>
          body{font-family:Segoe UI,Arial,sans-serif;background:#1e1e1e;color:#e0e0e0;margin:24px}
          h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;color:#9aa;margin:18px 0 6px}
          .sum{color:#9aa;margin-bottom:8px}
          table{border-collapse:collapse;width:100%}
          th,td{padding:6px 10px;border-bottom:1px solid #333;text-align:left;font-size:13px;vertical-align:top}
          th{color:#9aa;font-weight:600}
          .threat{color:#ff6b6b;font-weight:700}.clean{color:#6bd06b}.susp{color:#e0c060}
          tr:hover{background:#262626}a{color:#5ad}.small{color:#888;font-size:12px}
          .bar{display:inline-block;height:10px;background:#ff6b6b;border-radius:2px}
        </style></head><body>
        """);
        sb.AppendLine($"<h1>{H(AppConstants.AppTitle)} — güvenlik raporu</h1>");
        sb.AppendLine($"<div class=\"sum\">Aralık: <b>{H(rangeLabel)}</b> &nbsp;•&nbsp; Tarandı: {list.Count} &nbsp;•&nbsp; Tehdit: <b class=\"threat\">{threats}</b> &nbsp;•&nbsp; Temiz: <b class=\"clean\">{clean}</b></div>");

        // Source breakdown
        sb.AppendLine("<h2>Kaynak kırılımı</h2><div class=\"sum\">");
        foreach (var g in list.GroupBy(e => string.IsNullOrEmpty(e.Source) ? "—" : e.Source).OrderByDescending(g => g.Count()))
            sb.Append($"{H(g.Key)}: {g.Count()} &nbsp; ");
        sb.AppendLine("</div>");

        // Weekly trend (scanned + threats per ISO week)
        sb.AppendLine("<h2>Haftalık eğilim</h2><table><thead><tr><th>Hafta başı</th><th>Tarandı</th><th>Tehdit</th></tr></thead><tbody>");
        foreach (var g in list.GroupBy(e => e.WhenLocal.Date.AddDays(-((int)e.WhenLocal.DayOfWeek + 6) % 7)).OrderByDescending(g => g.Key))
        {
            int t = g.Count(e => VerdictCategories.IsThreat(e.Detections));
            sb.AppendLine($"<tr><td>{g.Key:yyyy-MM-dd}</td><td>{g.Count()}</td><td class=\"{(t > 0 ? "threat" : "")}\">{t} <span class=\"bar\" style=\"width:{Math.Min(160, t * 12)}px\"></span></td></tr>");
        }
        sb.AppendLine("</tbody></table>");

        // Threat rows
        var threatRows = list.Where(e => VerdictCategories.IsThreat(e.Detections)).ToList();
        sb.AppendLine($"<h2>Tehditler ({threatRows.Count})</h2>");
        sb.AppendLine("<table><thead><tr><th>Tarih</th><th>Dosya</th><th>Tespit</th><th>Kaynak</th><th>SHA-256</th></tr></thead><tbody>");
        foreach (var e in threatRows)
        {
            string fileCell = VtUrl(e) is { Length: > 0 } u ? $"<a href=\"{H(u)}\">{H(e.Name)}</a>" : H(e.Name);
            sb.AppendLine($"<tr><td>{e.WhenLocal:yyyy-MM-dd HH:mm}</td><td class=\"threat\">{fileCell}</td><td>{e.Detections}/{e.Total}</td><td>{H(e.Source)}</td><td class=\"small\">{H(e.Sha256 ?? "")}</td></tr>");
        }
        sb.AppendLine("</tbody></table></body></html>");
        return sb.ToString();
    }
}
