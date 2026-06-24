using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace VirusTotalScanner;

/// <summary>
/// The "is this safe?" answer, drawn large. An owner-drawn rounded card that replaces the thin verdict
/// banner: a circular badge (✓ / ! / ✕ / 🛡), the verdict word, the detection ratio, and a one-line
/// plain-language takeaway, all tinted with the verdict-category color so the answer reads in a glance.
/// </summary>
internal sealed class VerdictHeroPanel : Panel
{
    string _verdict = "", _sub = "", _takeaway = "", _glyph = "?";
    Color _accent = Color.Gray;

    public VerdictHeroPanel()
    {
        Dock = DockStyle.Fill;
        Height = 96;
        Margin = new Padding(0, 0, 0, 8);
        DoubleBuffered = true;
        SetStyle(ControlStyles.ResizeRedraw | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
        Theme.Changed += OnThemeChanged;
    }

    void OnThemeChanged() { try { if (IsHandleCreated) BeginInvoke(Invalidate); } catch { } }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Theme.Changed -= OnThemeChanged;
        base.Dispose(disposing);
    }

    public void Set(string verdict, string sub, string takeaway, string glyph, Color accent)
    {
        _verdict = verdict;
        _sub = sub;
        _takeaway = takeaway;
        _glyph = glyph;
        _accent = accent;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        var t = Theme.Current;
        g.Clear(t.Panel);

        var rect = ClientRectangle;
        rect.Width -= 1; rect.Height -= 1;
        rect.Inflate(-1, -1);

        // Tinted rounded background + subtle border in the verdict color.
        using (var bg = Rounded(rect, 14))
        {
            using var fill = new SolidBrush(Blend(_accent, t.Panel, 0.16f));
            g.FillPath(fill, bg);
            using var border = new Pen(Blend(_accent, t.Panel, 0.45f));
            g.DrawPath(border, bg);
        }

        // Solid left accent bar.
        var barRect = new Rectangle(rect.X + 6, rect.Y + 12, 6, rect.Height - 24);
        using (var bar = Rounded(barRect, 3))
        using (var barBrush = new SolidBrush(_accent))
            g.FillPath(barBrush, bar);

        // Circular badge with the status glyph.
        int d = 58, bx = rect.X + 26, by = rect.Y + (rect.Height - d) / 2;
        using (var badge = new SolidBrush(_accent))
            g.FillEllipse(badge, bx, by, d, d);
        using (var glyphFont = new Font("Segoe UI", 25f, FontStyle.Bold))
        using (var white = new SolidBrush(Color.White))
        {
            var fmt = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString(_glyph, glyphFont, white, new RectangleF(bx, by - 1, d, d), fmt);
        }

        // Text block: verdict word, ratio sub-line, takeaway.
        int tx = bx + d + 18;
        int tw = rect.Right - tx - 14;
        using var vFont = new Font("Segoe UI", 17f, FontStyle.Bold);
        using var sFont = new Font("Segoe UI", 10.5f, FontStyle.Regular);
        using var kFont = new Font("Segoe UI", 9.5f, FontStyle.Regular);
        using var textBrush = new SolidBrush(t.Text);
        using var subBrush = new SolidBrush(t.SubtleText);
        var ell = new StringFormat { Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };

        int ty = rect.Y + 16;
        g.DrawString(_verdict, vFont, textBrush, new RectangleF(tx, ty, tw, 28), ell);
        ty += 30;
        if (!string.IsNullOrEmpty(_sub)) { g.DrawString(_sub, sFont, subBrush, new RectangleF(tx, ty, tw, 20), ell); ty += 21; }
        if (!string.IsNullOrEmpty(_takeaway)) g.DrawString("👉  " + _takeaway, kFont, textBrush, new RectangleF(tx, ty, tw, 20), ell);
    }

    static Color Blend(Color a, Color b, float t) => Color.FromArgb(
        Clamp(a.R * t + b.R * (1 - t)), Clamp(a.G * t + b.G * (1 - t)), Clamp(a.B * t + b.B * (1 - t)));

    static int Clamp(double v) => v < 0 ? 0 : v > 255 ? 255 : (int)v;

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
