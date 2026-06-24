using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Lists quarantined files and restores them to their original path. Restore first re-checks
/// the current verdict (keyless) so reversing a false positive is safe, not blind.</summary>
internal sealed class QuarantineVaultDialog : Form
{
    readonly DataGridView _grid = new();
    readonly Label _sizeLabel = new() { AutoSize = true, Margin = new Padding(14, 9, 0, 0), Tag = "subtle" };

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
        _grid.MultiSelect = true;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColFile, DataPropertyName = nameof(QuarantineEntry.FileName), Width = 160 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColVerdict, DataPropertyName = nameof(QuarantineEntry.Verdict), Width = 90 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDetections, DataPropertyName = nameof(QuarantineEntry.Detections), Width = 60 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColDate, DataPropertyName = nameof(QuarantineEntry.QuarantinedUtc), Width = 130 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColOriginalPath, DataPropertyName = nameof(QuarantineEntry.OriginalPath), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });

        var restore = ThemeManager.MakeButton(Strings.BtnRestore, (_, _) => _ = RestoreSelectedAsync());
        var purge = ThemeManager.MakeButton("🗑  Kalıcı sil", (_, _) => PurgeSelected());
        var purgeAll = ThemeManager.MakeButton("🗑  Tümünü kalıcı sil", (_, _) => PurgeAll());
        var cleanup = ThemeManager.MakeButton("🧹  Eski kayıtları temizle…", (_, _) => CleanupOld());
        var close = new Button { Text = Strings.BtnClose, DialogResult = DialogResult.Cancel, Dock = DockStyle.Right, Width = 100 };
        var actions = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = false };
        actions.Controls.Add(restore);
        actions.Controls.Add(purge);
        actions.Controls.Add(purgeAll);
        actions.Controls.Add(cleanup);
        actions.Controls.Add(_sizeLabel);
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(10, 7, 10, 7) };
        bottom.Controls.Add(actions);
        bottom.Controls.Add(close);

        Controls.Add(_grid);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleGrid(_grid);
        ThemeManager.StyleButton(restore);
        ThemeManager.StyleButton(purge);
        ThemeManager.StyleButton(purgeAll);
        ThemeManager.StyleButton(cleanup);
        ThemeManager.StyleButton(close);
        Refresh2();
    }

    void Refresh2()
    {
        var list = QuarantineVault.List().ToList();
        _grid.DataSource = list;
        _sizeLabel.Text = $"{list.Count} dosya  •  geri kazanılabilir {FormatBytes(QuarantineVault.ReclaimableBytes())}";
    }

    List<QuarantineEntry> SelectedEntries() =>
        _grid.SelectedRows.Cast<DataGridViewRow>().Select(r => r.DataBoundItem).OfType<QuarantineEntry>().ToList();

    void PurgeSelected()
    {
        var entries = SelectedEntries();
        if (entries.Count == 0) return;
        string prompt = entries.Count == 1
            ? $"{entries[0].FileName} kalıcı olarak silinsin mi?\nBu geri ALINAMAZ (dosya kasadan tamamen kaldırılır)."
            : $"Seçili {entries.Count} dosya kalıcı olarak silinsin mi?\nBu geri ALINAMAZ.";
        if (!ConfirmGates.Quarantine.Ask(this, prompt)) return;
        int ok = entries.Count(e => QuarantineVault.Purge(e, out _));
        NativeMessageBox.Info($"{ok}/{entries.Count} kalıcı silindi.");
        Refresh2();
    }

    void PurgeAll()
    {
        var all = QuarantineVault.List().ToList();
        if (all.Count == 0) { NativeMessageBox.Info("Kasa zaten boş."); return; }
        if (!ConfirmGates.Quarantine.Ask(this, $"Kasadaki TÜM {all.Count} dosya kalıcı olarak silinsin mi?\nBu geri ALINAMAZ.")) return;
        int ok = all.Count(e => QuarantineVault.Purge(e, out _));
        NativeMessageBox.Info($"{ok}/{all.Count} kalıcı silindi.");
        Refresh2();
    }

    void CleanupOld()
    {
        string? input = Dialogs.InputBox("Kaç günden eski karantina kayıtları kalıcı silinsin?", "Eski kayıtları temizle", "30");
        if (!int.TryParse(input, out int days) || days <= 0) return;
        int n = QuarantineVault.PurgeOlderThan(days);
        NativeMessageBox.Info($"{n} kayıt kalıcı silindi.");
        Refresh2();
    }

    static string FormatBytes(long b)
    {
        string[] u = ["B", "KB", "MB", "GB", "TB"];
        double v = b; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }

    async Task RestoreSelectedAsync()
    {
        var entries = SelectedEntries();
        if (entries.Count == 0) return;

        if (entries.Count == 1)
        {
            var e = entries[0];
            // Re-check the current verdict so restoring a cleared false positive is safe (single only).
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
            if (QuarantineVault.Restore(e, out var err)) { NativeMessageBox.Info(string.Format(Strings.VaultRestoredFormat, e.OriginalPath)); Refresh2(); }
            else NativeMessageBox.Error(string.Format(Strings.VaultRestoreFailedFormat, err));
            return;
        }

        // Batch: one confirm for the whole set, then an aggregate result line.
        if (!NativeMessageBox.Confirm($"Seçili {entries.Count} dosya orijinal konumlarına geri yüklensin mi?")) return;
        int ok = entries.Count(e => QuarantineVault.Restore(e, out _));
        NativeMessageBox.Info($"{ok}/{entries.Count} geri yüklendi.");
        Refresh2();
    }
}
