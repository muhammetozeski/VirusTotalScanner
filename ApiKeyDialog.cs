using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Add/edit a VirusTotal API key, with show/hide and a "Validate" button.</summary>
internal sealed class ApiKeyDialog : Form
{
    readonly TextBox _label = new();
    readonly TextBox _key = new();
    readonly CheckBox _show = new();
    readonly Label _status = new();

    public string KeyLabel => _label.Text.Trim();
    public string KeyValue => _key.Text.Trim();

    public ApiKeyDialog(string? label = null, string? key = null)
    {
        Text = key == null ? "API anahtarı ekle" : "API anahtarını düzenle";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;
        ClientSize = new Size(500, 220);

        var l1 = new Label { Text = "Etiket (isteğe bağlı):", Left = 14, Top = 16, AutoSize = true };
        _label.SetBounds(14, 38, 472, 24);
        _label.Text = label ?? "";

        var l2 = new Label { Text = "VirusTotal API anahtarı:", Left = 14, Top = 72, AutoSize = true };
        _key.SetBounds(14, 94, 472, 24);
        _key.UseSystemPasswordChar = true;
        _key.Font = new Font("Consolas", 9.5f);
        _key.Text = key ?? "";

        _show.Text = "Göster";
        _show.SetBounds(14, 124, 80, 22);
        _show.CheckedChanged += (_, _) => _key.UseSystemPasswordChar = !_show.Checked;

        _status.SetBounds(100, 124, 386, 22);
        _status.AutoEllipsis = true;
        _status.Tag = "subtle";

        var validate = ThemeManager.MakeButton("Doğrula", async (_, _) => await ValidateAsync());
        validate.SetBounds(14, 160, 110, 32);

        var ok = new Button { Text = "Kaydet", DialogResult = DialogResult.OK, Left = 320, Top = 160, Width = 80, Height = 32 };
        var cancel = new Button { Text = "İptal", DialogResult = DialogResult.Cancel, Left = 406, Top = 160, Width = 80, Height = 32 };
        ok.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(_key.Text)) { DialogResult = DialogResult.None; NativeMessageBox.Warn("Anahtar boş olamaz."); }
        };

        Controls.AddRange([l1, _label, l2, _key, _show, _status, validate, ok, cancel]);
        AcceptButton = ok;
        CancelButton = cancel;
        ThemeManager.Apply(this);
        ThemeManager.StyleButton(ok);
        ThemeManager.StyleButton(cancel);
    }

    async Task ValidateAsync()
    {
        string key = _key.Text.Trim();
        if (string.IsNullOrWhiteSpace(key)) { _status.Text = "Önce anahtarı girin."; return; }
        _status.ForeColor = Theme.Current.SubtleText;
        _status.Text = "Doğrulanıyor…";
        try
        {
            var q = await AppServices.Api.GetUserQuotaAsync(key);
            if (q == null) { _status.ForeColor = Theme.Current.Warning; _status.Text = "Yanıt alındı ama kota okunamadı (anahtar yine de çalışabilir)."; return; }
            _status.ForeColor = Theme.Current.Success;
            _status.Text = $"Geçerli ✓  Günlük {q.Daily.Used}/{q.Daily.Allowed} • Aylık {q.Monthly.Used}/{q.Monthly.Allowed}";
        }
        catch (VtAuthException) { _status.ForeColor = Theme.Current.Danger; _status.Text = "Geçersiz anahtar (401/403)."; }
        catch (Exception ex) { _status.ForeColor = Theme.Current.Danger; _status.Text = "Hata: " + ex.Message; }
    }
}
