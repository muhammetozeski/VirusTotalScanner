using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Lists quarantined files and restores them to their original path. Restore first re-checks
/// the current verdict (keyless) so reversing a false positive is safe, not blind.</summary>
internal sealed class QuarantineVaultDialog : Form
{
    readonly DataGridView _grid = new();

    public QuarantineVaultDialog()
    {
        Text = Strings.DlgVaultTitle;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(860, 460);
        MinimumSize = new Size(620, 320);

        _grid.Dock = DockStyle.Fill;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.ReadOnly = true;
        _grid.RowHeadersVisible = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(QuarantineEntry.FileName), Width = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColVerdict, DataPropertyName = nameof(QuarantineEntry.Verdict), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDetections, DataPropertyName = nameof(QuarantineEntry.Detections), Width = 60 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDate, DataPropertyName = nameof(QuarantineEntry.QuarantinedUtc), Width = 130 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColOriginalPath, DataPropertyName = nameof(QuarantineEntry.OriginalPath), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

        var restore = ThemeManager.MakeButton(Strings.BtnRestore, (_, _) => _ = RestoreSelectedAsync());
        var close = new Button { Text = Strings.BtnClose, DialogResult = DialogResult.Cancel, Dock = DockStyle.Right, Width = 100 };
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
                    !NativeMessageBox.Confirm(string.Format(Strings.VaultStillMaliciousFormat, e.FileName, r.DetectionCount, r.TotalEngines)))
                    return;
            }
            catch (Exception ex) { Log("Vault restore recheck failed: " + ex.Message, LogLevel.Warning); }
        }

        if (!NativeMessageBox.Confirm(string.Format(Strings.VaultRestoreConfirmFormat, e.FileName, e.OriginalPath))) return;

        if (QuarantineVault.Restore(e, out var err))
        {
            NativeMessageBox.Info(string.Format(Strings.VaultRestoredFormat, e.OriginalPath));
            Refresh2();
        }
        else NativeMessageBox.Error(string.Format(Strings.VaultRestoreFailedFormat, err));
    }
}
