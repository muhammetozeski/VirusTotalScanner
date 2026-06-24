using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Text;

namespace VirusTotalScanner;

/// <summary>Renders a scan result as a clean, self-contained card — a PNG to paste into a chat ("is
/// this safe?") or a compact text block for a terminal/commit. Off-screen GDI+ at 2× so it stays crisp
/// when pasted; honors the active theme and the user's verdict colors so it matches the screen.</summary>
internal static class ShareCard
{
    const int W = 560, H = 300, Scale = 2;

    public static Bitmap Render(ScanItem item)
    {
        var t = Theme.Current;
        var report = item.Report;
        string verdict = item.Verdict.Length > 0 ? item.Verdict : (report?.Verdict ?? "?");
        var accent = report != null ? Theme.VerdictColor(verdict)
            : item.Status == ScanStatus.TrustedSkipped ? t.Accent : t.SubtleText;
        int det = report?.DetectionCount ?? 0, total = report?.TotalEngines ?? 0;

        var bmp = new Bitmap(W * Scale, H * Scale);
        using var g = Graphics.FromImage(bmp);
        g.ScaleTransform(Scale, Scale);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        g.Clear(t.Background);

        // Header band in the verdict color.
        using (var head = new SolidBrush(accent)) g.FillRectangle(head, 0, 0, W, 72);
        using (var vf = new Font("Segoe UI", 20f, FontStyle.Bold))
        using (var white = new SolidBrush(Color.White))
        {
            g.DrawString(verdict, vf, white, 18, 12);
            string sub = total > 0 ? $"{det}/{total} motor tespit etti"
                : item.Status == ScanStatus.TrustedSkipped ? "İmzalı — VT taraması atlandı" : "bilinmiyor";
            using var sf = new Font("Segoe UI", 10.5f);
            g.DrawString(sub, sf, white, 20, 46);
        }

        using var text = new SolidBrush(t.Text);
        using var subtle = new SolidBrush(t.SubtleText);
        using var nameFont = new Font("Segoe UI", 13f, FontStyle.Bold);
        using var bodyFont = new Font("Segoe UI", 9.5f);
        using var mono = new Font("Consolas", 8.5f);

        int y = 84;
        g.DrawString(Trim(report?.MeaningfulName ?? item.FileName, 56), nameFont, text, 18, y); y += 26;

        // Detection ratio bar.
        if (total > 0)
        {
            int bx = 18, bw = W - 36, bh = 14;
            using (var track = new SolidBrush(Blend(t.SubtleText, t.Background, 0.3f)))
            using (var path = Rounded(new Rectangle(bx, y, bw, bh), 7))
                g.FillPath(track, path);
            int fill = (int)(bw * Math.Min(1.0, det / (double)total));
            if (fill > 0)
                using (var fb = new SolidBrush(accent))
                using (var fp = Rounded(new Rectangle(bx, y, Math.Max(fill, 14), bh), 7))
                    g.FillPath(fb, fp);
            y += bh + 10;
        }

        // Signal lines.
        foreach (var line in BodyLines(item).Take(5))
        {
            g.DrawString(line, bodyFont, subtle, 18, y);
            y += 18;
        }

        // Hashes + footer.
        string sha = item.Sha256 ?? report?.Sha256 ?? "";
        if (sha.Length > 0) g.DrawString("SHA-256  " + sha, mono, subtle, 18, H - 50);
        using (var fpen = new Pen(Blend(t.SubtleText, t.Background, 0.4f))) g.DrawLine(fpen, 18, H - 28, W - 18, H - 28);
        g.DrawString($"{AppConstants.AppTitle} • {DateTime.Now:yyyy-MM-dd}", bodyFont, subtle, 18, H - 22);

        return bmp;
    }

    public static string Text(ScanItem item)
    {
        var r = item.Report;
        var sb = new StringBuilder();
        string verdict = item.Verdict.Length > 0 ? item.Verdict : (r?.Verdict ?? "?");
        sb.AppendLine($"[{verdict}{(r != null && r.TotalEngines > 0 ? $" {r.DetectionCount}/{r.TotalEngines}" : "")}] {item.FileName}");
        if (r?.ThreatLabel is { Length: > 0 } tl) sb.AppendLine("Tür: " + tl);
        else if (r?.Family is { Length: > 0 } fam) sb.AppendLine("Aile: " + fam);
        if (r?.FirstSeenText is { } fs) sb.AppendLine(fs);
        if (item.Md5 is { Length: > 0 } md5) sb.AppendLine("MD5    " + md5);
        if ((item.Sha256 ?? r?.Sha256) is { Length: > 0 } sha) sb.AppendLine("SHA256 " + sha);
        if (r != null) sb.AppendLine(r.ReportUrl);
        return sb.ToString().TrimEnd();
    }

    /// <summary>A Markdown rendering of the same fields as <see cref="Text"/> — heading, inline-code hashes
    /// and a clickable report link — so a pasted summary renders cleanly in GitHub/Discord/PR descriptions.</summary>
    public static string Markdown(ScanItem item)
    {
        var r = item.Report;
        var sb = new StringBuilder();
        string verdict = item.Verdict.Length > 0 ? item.Verdict : (r?.Verdict ?? "?");
        string ratio = r != null && r.TotalEngines > 0 ? $" {r.DetectionCount}/{r.TotalEngines}" : "";
        sb.AppendLine($"### [{verdict}{ratio}] {item.FileName}");
        sb.AppendLine();
        if (r?.ThreatLabel is { Length: > 0 } tl) sb.AppendLine("- **Tür:** " + tl);
        else if (r?.Family is { Length: > 0 } fam) sb.AppendLine("- **Aile:** " + fam);
        if (r?.FirstSeenText is { } fs) sb.AppendLine("- " + fs);
        if (item.Md5 is { Length: > 0 } md5) sb.AppendLine("- **MD5:** `" + md5 + "`");
        if ((item.Sha256 ?? r?.Sha256) is { Length: > 0 } sha) sb.AppendLine("- **SHA-256:** `" + sha + "`");
        if (r != null && !string.IsNullOrEmpty(r.ReportUrl)) sb.AppendLine("- [VirusTotal raporu](" + r.ReportUrl + ")");
        return sb.ToString().TrimEnd();
    }

    static List<string> BodyLines(ScanItem item)
    {
        var r = item.Report;
        var lines = new List<string>();
        if (r == null) return lines;
        if (r.ThreatLabel is { Length: > 0 } tl) lines.Add("🏷 " + tl);
        else if (r.FamilyLabel is { } fl) lines.Add(fl);
        if (r.ConsensusText is { } c) lines.Add(c);
        if (r.FirstSeenText is { } fs) lines.Add(fs);
        if (r.CapabilitySummary is { } cap) lines.Add(cap);
        if (ZoneIdentifier.Read(item.FilePath)?.Summary is { } z) lines.Add(z);
        return lines;
    }

    static string Trim(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    static Color Blend(Color a, Color b, float t) => Color.FromArgb(
        (int)(a.R * t + b.R * (1 - t)), (int)(a.G * t + b.G * (1 - t)), (int)(a.B * t + b.B * (1 - t)));

    static GraphicsPath Rounded(Rectangle r, int radius)
    {
        var p = new GraphicsPath();
        int d = radius * 2;
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }
}
