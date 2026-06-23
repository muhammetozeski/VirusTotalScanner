using System.Drawing;

namespace VirusTotalScanner;

internal enum QuotaExhaustedChoice { Wait, Keyless, NewKey }

/// <summary>
/// Shown once when every API key's quota is exhausted during a scan: wait for the soonest reset,
/// switch to the keyless GUI engine (no quota, slower), or add a new API key.
/// </summary>
internal sealed class QuotaExhaustedDialog : Form
{
    public QuotaExhaustedChoice Choice { get; private set; } = QuotaExhaustedChoice.Wait;

    public QuotaExhaustedDialog(DateTime resumeUtc)
    {
        Text = "API kotası doldu";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;
        ClientSize = new Size(470, 214);

        var localResume = resumeUtc.ToLocalTime();
        var msg = new Label
        {
            Left = 16,
            Top = 14,
            Width = 438,
            Height = 64,
            AutoSize = false,
            Text = $"Tüm API anahtarlarının kotası doldu.\nEn erken sıfırlanma: {localResume:HH:mm} (yerel saat).\n\nNe yapmak istersiniz?",
        };

        var wait = MakeChoice("⏳  Bekle — sıfırlanınca otomatik devam et", QuotaExhaustedChoice.Wait, 86);
        var keyless = MakeChoice("🌐  Anahtarsız (GUI) moda geç — kotasız, daha yavaş", QuotaExhaustedChoice.Keyless, 124);
        var newKey = MakeChoice("🔑  Yeni API anahtarı ekle", QuotaExhaustedChoice.NewKey, 162);

        Controls.AddRange([msg, wait, keyless, newKey]);
        AcceptButton = wait;
        ThemeManager.Apply(this);
    }

    Button MakeChoice(string text, QuotaExhaustedChoice choice, int top)
    {
        var b = new Button
        {
            Text = text,
            Left = 16,
            Top = top,
            Width = 438,
            Height = 34,
            TextAlign = ContentAlignment.MiddleLeft,
        };
        b.Click += (_, _) => { Choice = choice; DialogResult = DialogResult.OK; };
        ThemeManager.StyleButton(b);
        return b;
    }
}
