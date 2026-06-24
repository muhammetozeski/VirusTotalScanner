using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Lists the autostart hooks pointing at a (usually flagged) file and lets the user reversibly
/// cut each one — closing the gap between "flagged" and "actually removed" without hand-editing regedit.</summary>
internal sealed class PersistenceHooksDialog : Form
{
    readonly DataGridView _grid = new();
    readonly List<PersistenceHunter.Hook> _hooks;

    public PersistenceHooksDialog(string fileName, List<PersistenceHunter.Hook> hooks)
    {
        _hooks = hooks;
        Text = "🔗 Autostart kancaları — " + fileName;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(820, 420);
        MinimumSize = new Size(600, 320);

        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Konum", DataPropertyName = nameof(PersistenceHunter.Hook.Location), Width = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Ad", DataPropertyName = nameof(PersistenceHunter.Hook.Name), Width = 170 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Komut", DataPropertyName = nameof(PersistenceHunter.Hook.Command), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        RefreshGrid();

        var remove = ThemeManager.MakeButton("🗑  Seçili kancayı kaldır", (_, _) => RemoveSelected(), accent: true);
        var close = new Button { Text = "Kapat", DialogResult = DialogResult.Cancel, Width = 90 };

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(8) };
        top.Controls.Add(new Label { Text = $"{hooks.Count} kalıcılık kancası bulundu. Kaldırma geri alınabilir: kayıt değeri quarantine\\autostart-restore.log'a yazılır, Başlangıç .lnk'i kasaya taşınır.", AutoSize = true, Margin = new Padding(0, 4, 0, 0) });

        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 44, Padding = new Padding(10, 6, 10, 6) };
        remove.Dock = DockStyle.Left;
        close.Dock = DockStyle.Right;
        bottom.Controls.Add(remove);
        bottom.Controls.Add(close);

        Controls.Add(_grid);
        Controls.Add(top);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(_grid);
        ThemeManager.StyleButton(remove);
        ThemeManager.StyleButton(close);
    }

    void RefreshGrid() => _grid.DataSource = _hooks.ToList();

    void RemoveSelected()
    {
        if (_grid.CurrentRow?.DataBoundItem is not PersistenceHunter.Hook h) return;
        if (!ConfirmGates.Quarantine.Ask(this, $"Bu autostart kancası kaldırılsın mı?\n[{h.Location}] {h.Name}")) return;
        if (PersistenceHunter.Remove(h, out var err))
        {
            _hooks.Remove(h);
            RefreshGrid();
            NativeMessageBox.Info("Kanca kaldırıldı (geri alınabilir).");
        }
        else NativeMessageBox.Error("Kaldırılamadı: " + (err ?? "bilinmeyen hata") + "\n(HKLM kancaları yönetici hakları gerektirir.)");
    }
}
