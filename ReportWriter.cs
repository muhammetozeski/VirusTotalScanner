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
}
