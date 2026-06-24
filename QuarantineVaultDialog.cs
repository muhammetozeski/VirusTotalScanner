using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Lists quarantined files and restores them to their original path. Restore first re-checks
/// the current verdict (keyless) so reversing a false positive is safe, not blind.</summary>
internal sealed class QuarantineVaultDialog : Form
{
    readonly DataGridView _grid = new();

    public QuarantineVaultDialog()
    {
        Text = "🗄 Karantina kasası";
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(860, 460);
        MinimumSize = new Size(620, 320);

        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Dosya", DataPropertyName = nameof(QuarantineEntry.FileName), Width = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Verdikt", DataPropertyName = nameof(QuarantineEntry.Verdict), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tespit", DataPropertyName = nameof(QuarantineEntry.Detections), Width = 60 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Tarih (UTC)", DataPropertyName = nameof(QuarantineEntry.QuarantinedUtc), Width = 130 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Orijinal konum", DataPropertyName = nameof(QuarantineEntry.OriginalPath), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

        var restore = ThemeManager.MakeButton("↩  Geri yükle", (_, _) => _ = RestoreSelectedAsync());
        var close = new Button { Text = "Kapat", DialogResult = DialogResult.Cancel, Dock = DockStyle.Right, Width = 100 };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(10, 7, 10, 7) };
        bottom.Controls.Add(close);
        bottom.Controls.Add(restore);

        Controls.Add(_grid);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(_grid);
        ThemeManager.StyleButton(restore);
        ThemeManager.StyleButton(close);
        Refresh2();
    }

    void Refresh2() => _grid.DataSource = QuarantineVault.List().ToList();

    QuarantineEntry? Selected() => _grid.CurrentRow?.DataBoundItem as QuarantineEntry;

    async Task RestoreSelectedAsync()
    {
        var e = Selected();
        if (e == null) return;

        // Re-check the current verdict so restoring a cleared false positive is safe.
        if (!string.IsNullOrWhiteSpace(e.Sha256) && Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable)
        {
            try
            {
                var fresh = await GuiScrapeService.LookupAsync(e.Sha256!);
                if (fresh is { } r && r.IsMalicious &&
                    !NativeMessageBox.Confirm($"DİKKAT: '{e.FileName}' hâlâ zararlı görünüyor ({r.DetectionCount}/{r.TotalEngines}). Yine de geri yüklensin mi?"))
                    return;
            }
            catch (Exception ex) { Log("Vault restore recheck failed: " + ex.Message, LogLevel.Warning); }
        }

        if (!NativeMessageBox.Confirm($"'{e.FileName}' şu konuma geri yüklensin mi?\n{e.OriginalPath}")) return;

        if (QuarantineVault.Restore(e, out var err))
        {
            NativeMessageBox.Info("Geri yüklendi: " + e.OriginalPath);
            Refresh2();
        }
        else NativeMessageBox.Error("Geri yüklenemedi: " + err);
    }
}
