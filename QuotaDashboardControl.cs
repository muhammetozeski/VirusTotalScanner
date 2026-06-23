using System.Drawing;

namespace VirusTotalScanner;

/// <summary>A thin custom-painted usage meter (used / allowed).</summary>
internal sealed class MeterBar : Panel
{
    // Public fields (not properties) to avoid the WinForms designer-serialization analyzer;
    // this control is only ever created in code.
    public long Value;
    public long Max = 1;
    public Color BarColor = Color.SteelBlue;

    public MeterBar() { Height = 14; DoubleBuffered = true; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var p = Theme.Current;
        var rect = ClientRectangle;
        using (var bg = new SolidBrush(p.Border)) e.Graphics.FillRectangle(bg, rect);
        if (Max > 0 && Value > 0)
        {
            int w = (int)(rect.Width * Math.Min(1.0, (double)Value / Max));
            var c = (double)Value / Max >= 1.0 ? p.Danger : BarColor;
            using var fb = new SolidBrush(c);
            e.Graphics.FillRectangle(fb, 0, 0, w, rect.Height);
        }
    }
}

/// <summary>
/// "Kotalar" tab: one card per API key with minute/daily/monthly meters + reset countdowns,
/// an "all exhausted, resuming in mm:ss" banner, and a button to reconcile usage from the
/// server. Counters update live as scans consume quota.
/// </summary>
internal sealed class QuotaDashboardControl : UserControl
{
    readonly Label _banner = new();
    readonly FlowLayoutPanel _flow = new();
    readonly System.Windows.Forms.Timer _timer = new() { Interval = 1000 };
    readonly List<Action<DateTime>> _updaters = [];
    DateTime? _resumeAtUtc;

    public QuotaDashboardControl()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(10);

        _banner.Dock = DockStyle.Top;
        _banner.Height = 36;
        _banner.TextAlign = ContentAlignment.MiddleCenter;
        _banner.Font = new Font("Segoe UI", 10f, FontStyle.Bold);
        _banner.Visible = false;

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(0, 0, 0, 6) };
        top.Controls.Add(ThemeManager.MakeButton("↻  Sunucudan kotayı yenile", (_, _) => _ = RefreshFromServerAsync()));
        top.Controls.Add(ThemeManager.MakeLabel("  4 sorgu/dk • 500/gün • 15.5K/ay (anahtar başına)", subtle: true));

        _flow.Dock = DockStyle.Fill;
        _flow.AutoScroll = true;
        _flow.WrapContents = true;
        _flow.FlowDirection = FlowDirection.LeftToRight;

        Controls.Add(_flow);
        Controls.Add(top);
        Controls.Add(_banner);

        AppServices.Vault.Changed += () => SafeUi(BuildCards);
        AppServices.Vault.CountersUpdated += () => SafeUi(() => Tick());
        AppServices.Rotator.OnAllExhausted += t => SafeUi(() => { _resumeAtUtc = t; });
        AppServices.Rotator.OnResumed += () => SafeUi(() => { _resumeAtUtc = null; _banner.Visible = false; });

        _timer.Tick += (_, _) => Tick();
        _timer.Start();

        BuildCards();
    }

    void BuildCards()
    {
        _flow.SuspendLayout();
        _flow.Controls.Clear();
        _updaters.Clear();

        var keys = AppServices.Vault.Keys;
        if (keys.Count == 0)
        {
            var empty = ThemeManager.MakeLabel("Henüz API anahtarı yok. Ayarlar sekmesinden ekleyin.", subtle: true);
            _flow.Controls.Add(empty);
        }
        foreach (var entry in keys)
            _flow.Controls.Add(BuildCard(entry));

        _flow.ResumeLayout();
        ThemeManager.Apply(this);
        Tick();
    }

    Control BuildCard(ApiKeyEntry entry)
    {
        var card = ThemeManager.MakeCard();
        card.Width = 320;
        card.Height = 188;

        var title = new Label
        {
            Text = (string.IsNullOrWhiteSpace(entry.Label) ? "Key" : entry.Label) + "  •  " + entry.Masked,
            Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
            AutoSize = true,
            Location = new Point(12, 10),
        };
        var status = new Label { AutoSize = true, Location = new Point(12, 34), Tag = "subtle" };

        card.Controls.Add(title);
        card.Controls.Add(status);

        var (mMeter, mLabel) = AddMeter(card, "Dakika", 58, Theme.Current.Accent);
        var (dMeter, dLabel) = AddMeter(card, "Günlük", 98, Theme.Current.Success);
        var (yMeter, yLabel) = AddMeter(card, "Aylık", 138, Color.MediumPurple);

        _updaters.Add(nowUtc =>
        {
            entry.Minute.Roll(nowUtc); entry.Daily.Roll(nowUtc); entry.Monthly.Roll(nowUtc);
            SetMeter(mMeter, mLabel, entry.Minute, nowUtc, "dk");
            SetMeter(dMeter, dLabel, entry.Daily, nowUtc, "gün");
            SetMeter(yMeter, yLabel, entry.Monthly, nowUtc, "ay");
            status.Text = entry.Disabled ? "● Devre dışı: " + (entry.LastError ?? "auth")
                : entry.IsExhausted(nowUtc) ? "● Dolu — bekleniyor" : "● Aktif";
            status.ForeColor = entry.Disabled ? Theme.Current.Danger
                : entry.IsExhausted(nowUtc) ? Theme.Current.Warning : Theme.Current.Success;
        });

        return card;
    }

    (MeterBar, Label) AddMeter(Panel card, string name, int top, Color color)
    {
        var nameLbl = new Label { Text = name, AutoSize = true, Location = new Point(12, top), Width = 60 };
        var meter = new MeterBar { Location = new Point(12, top + 18), Width = 220, BarColor = color };
        var valLbl = new Label { AutoSize = true, Location = new Point(238, top + 16), Tag = "subtle", Font = new Font("Segoe UI", 8f) };
        card.Controls.Add(nameLbl);
        card.Controls.Add(meter);
        card.Controls.Add(valLbl);
        return (meter, valLbl);
    }

    static void SetMeter(MeterBar meter, Label label, QuotaWindow w, DateTime nowUtc, string unit)
    {
        meter.Value = w.Used;
        meter.Max = Math.Max(1, w.Allowed);
        meter.Invalidate();
        string reset = w.HasRoom ? "" : "  •  " + FormatCountdown(w.ResetUtc - nowUtc);
        label.Text = $"{w.Used}/{w.Allowed}{reset}";
    }

    void Tick()
    {
        var now = DateTime.UtcNow;
        foreach (var u in _updaters) { try { u(now); } catch { } }

        if (_resumeAtUtc is { } at)
        {
            var left = at - now;
            if (left <= TimeSpan.Zero) { _banner.Visible = false; }
            else
            {
                _banner.Visible = true;
                _banner.BackColor = Theme.Current.Warning;
                _banner.ForeColor = Color.Black;
                _banner.Text = $"Tüm anahtarlar dolu — {FormatCountdown(left)} sonra otomatik devam edilecek…";
            }
        }
    }

    async Task RefreshFromServerAsync()
    {
        foreach (var entry in AppServices.Vault.Keys)
        {
            if (entry.Disabled) continue;
            try
            {
                var q = await AppServices.Api.GetUserQuotaAsync(entry.Key);
                if (q != null) AppServices.Rotator.ReconcileFromServer(entry.Key, q);
            }
            catch (Exception ex) { Log($"Quota refresh failed for {entry.Masked}: {ex.Message}", LogLevel.Warning); }
        }
        SafeUi(Tick);
    }

    static string FormatCountdown(TimeSpan t)
    {
        if (t < TimeSpan.Zero) t = TimeSpan.Zero;
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours}sa {t.Minutes}dk";
        if (t.TotalMinutes >= 1) return $"{t.Minutes}dk {t.Seconds}sn";
        return $"{t.Seconds}sn";
    }

    void SafeUi(Action a) { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch { } }

    public void ApplyTheme() => BuildCards();
}
