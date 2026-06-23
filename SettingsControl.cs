using System.Drawing;

namespace VirusTotalScanner;

/// <summary>"Ayarlar" tab: API keys CRUD, context-menu install/repair/uninstall, scan and
/// general preferences. Every change is persisted immediately.</summary>
internal sealed class SettingsControl : UserControl
{
    sealed class KeyRow
    {
        // Properties (not fields) — DataGridView data binding only binds to properties.
        public string Id { get; set; } = "";
        public string Label { get; set; } = "";
        public string Anahtar { get; set; } = "";
        public string Durum { get; set; } = "";
    }

    readonly FlowLayoutPanel _flow = new();
    readonly DataGridView _keysGrid = new();
    readonly Label _menuStatus = new();

    public SettingsControl()
    {
        Dock = DockStyle.Fill;
        _flow.Dock = DockStyle.Fill;
        _flow.FlowDirection = FlowDirection.TopDown;
        _flow.WrapContents = false;
        _flow.AutoScroll = true;
        _flow.Padding = new Padding(10);
        Controls.Add(_flow);

        _flow.Controls.Add(BuildKeysCard());
        _flow.Controls.Add(BuildContextMenuCard());
        _flow.Controls.Add(BuildTrustCard());
        _flow.Controls.Add(BuildVerdictCard());
        _flow.Controls.Add(BuildScanCard());
        _flow.Controls.Add(BuildGeneralCard());
        _flow.Controls.Add(BuildConfirmGatesCard());
        _flow.Controls.Add(BuildAboutCard());

        Resize += (_, _) => ResizeCards();
        _flow.Resize += (_, _) => ResizeCards();
        AppServices.Vault.Changed += () => SafeUi(RefreshKeys);

        RefreshKeys();
        RefreshMenuStatus();
    }

    void ResizeCards()
    {
        int w = _flow.ClientSize.Width - 28;
        if (w < 200) return;
        foreach (Control c in _flow.Controls) c.Width = w;
    }

    Panel BuildKeysCard()
    {
        var card = Card("API Anahtarları", 270, out var body);

        _keysGrid.Dock = DockStyle.Top;
        _keysGrid.Height = 150;
        _keysGrid.AutoGenerateColumns = false;
        _keysGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Etiket", DataPropertyName = nameof(KeyRow.Label), Width = 160 });
        _keysGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Anahtar", DataPropertyName = nameof(KeyRow.Anahtar), Width = 160 });
        _keysGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Durum", DataPropertyName = nameof(KeyRow.Durum), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        ThemeManager.StyleGrid(_keysGrid);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(0, 6, 0, 0) };
        buttons.Controls.Add(ThemeManager.MakeButton("Ekle…", (_, _) => AddKey(), accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton("Düzenle…", (_, _) => EditKey()));
        buttons.Controls.Add(ThemeManager.MakeButton("Sil", (_, _) => RemoveKey()));
        var hint = ThemeManager.MakeLabel("Birden çok anahtar ekleyebilirsiniz; biri dolunca diğerine geçilir.", subtle: true);

        body.Controls.Add(hint);
        body.Controls.Add(buttons);
        body.Controls.Add(_keysGrid);
        return card;
    }

    Panel BuildContextMenuCard()
    {
        var card = Card("Sağ Tuş Menüsü", 180, out var body);
        _menuStatus.AutoSize = true;
        _menuStatus.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);

        var excludeSafe = new CheckBox { Text = "Güvenli türlerde (txt, resim, video…) menüde gösterme", AutoSize = true, Checked = Settings.ContextMenuExcludeSafe };
        excludeSafe.CheckedChanged += (_, _) => { Settings.ContextMenuExcludeSafe.Value = excludeSafe.Checked; SettingsManager.SaveSettings(); };

        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        buttons.Controls.Add(ThemeManager.MakeButton("Sağ tuşa ekle (yönetici)", (_, _) => InstallMenu(), accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton("Onar", (_, _) => RunMenuOp(() => ContextMenuInstaller.Repair(out var e), "Onarıldı.")));
        buttons.Controls.Add(ThemeManager.MakeButton("Kaldır", (_, _) => RunMenuOp(() => ContextMenuInstaller.Uninstall(out var e), "Kaldırıldı.")));

        body.Controls.Add(excludeSafe);
        body.Controls.Add(buttons);
        body.Controls.Add(_menuStatus);
        return card;
    }

    Panel BuildTrustCard()
    {
        var card = Card("Güven Kaynakları (kota tasarrufu)", 330, out var body);

        var info = ThemeManager.MakeLabel(
            "Geçerli kod imzası olan dosyalar kota harcamamak için VT'ye gönderilmez.\n" +
            "Not: imza güveni = yayıncı doğrulandı demektir, \"temiz\" garantisi değildir.", subtle: true);

        var skipSigned = new CheckBox { Text = "İmzalı dosyaları VT'ye gönderme (anahtarsız, sınırsız)", AutoSize = true, Checked = Settings.TrustSkipSigned };
        skipSigned.CheckedChanged += (_, _) => { Settings.TrustSkipSigned.Value = skipSigned.Checked; SettingsManager.SaveSettings(); };

        var msOnly = new CheckBox { Text = "Yalnızca Microsoft imzalı dosyaları atla (güvenli varsayılan)", AutoSize = true, Checked = Settings.TrustMicrosoftOnly };
        msOnly.CheckedChanged += (_, _) => { Settings.TrustMicrosoftOnly.Value = msOnly.Checked; SettingsManager.SaveSettings(); };

        var allowLbl = ThemeManager.MakeLabel("Ek güvenilen yayıncılar (CN, ; ile ayır):");
        var allow = new TextBox { Dock = DockStyle.Top, Text = Settings.TrustPublisherAllowList };
        allow.Leave += (_, _) => { Settings.TrustPublisherAllowList.Value = allow.Text.Trim(); SettingsManager.SaveSettings(); };

        var dbRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top };
        var dbBox = new TextBox { Width = 360, Text = Settings.KnownGoodHashDbPath, ReadOnly = true };
        var pick = ThemeManager.MakeButton("Bilinen-temiz hash listesi seç…", (_, _) =>
        {
            using var dlg = new OpenFileDialog { Filter = "Metin/hash listesi|*.txt;*.csv;*.*" };
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                Settings.KnownGoodHashDbPath.Value = dlg.FileName;
                SettingsManager.SaveSettings();
                dbBox.Text = dlg.FileName;
                KnownGoodDb.Reload();
                NativeMessageBox.Info($"{KnownGoodDb.Count} hash yüklendi.");
            }
        });
        dbRow.Controls.Add(dbBox);
        dbRow.Controls.Add(pick);

        var keyless = new CheckBox { Text = "Anahtarsız sorgu: VirusTotal'i GUI üzerinden aç (yavaş, kotasız)", AutoSize = true, Checked = Settings.KeylessGuiLookup };
        keyless.CheckedChanged += (_, _) => { Settings.KeylessGuiLookup.Value = keyless.Checked; SettingsManager.SaveSettings(); };

        body.Controls.Add(info);
        body.Controls.Add(skipSigned);
        body.Controls.Add(keyless);
        body.Controls.Add(msOnly);
        body.Controls.Add(allowLbl);
        body.Controls.Add(allow);
        body.Controls.Add(dbRow);
        return card;
    }

    System.ComponentModel.BindingList<VerdictCategory>? _catRows;
    DataGridView? _catGrid;

    Panel BuildVerdictCard()
    {
        var card = Card("Verdict Kategorileri (tespit sayısı → ad + renk)", 250, out var body);

        _catGrid = new DataGridView { Dock = DockStyle.Top, Height = 130, AutoGenerateColumns = false };
        _catGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Min. tespit", DataPropertyName = nameof(VerdictCategory.MinDetections), Width = 90 });
        _catGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Ad", DataPropertyName = nameof(VerdictCategory.Name), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _catGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Renk", Width = 110, ReadOnly = true });
        _catGrid.ReadOnly = false;
        _catGrid.AllowUserToAddRows = false;
        _catGrid.CellFormatting += (_, e) =>
        {
            if (e.ColumnIndex == 2 && _catGrid.Rows[e.RowIndex].DataBoundItem is VerdictCategory c)
            {
                e.Value = c.ColorHex;
                e.CellStyle!.BackColor = c.Color;
                e.CellStyle.ForeColor = c.Color.GetBrightness() < 0.5 ? System.Drawing.Color.White : System.Drawing.Color.Black;
            }
        };
        ThemeManager.StyleGrid(_catGrid);
        _catGrid.ReadOnly = false; // re-enable after StyleGrid (which sets ReadOnly=true)

        RefreshCats();

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
        buttons.Controls.Add(ThemeManager.MakeButton("Ekle", (_, _) =>
        {
            int next = (_catRows!.Count == 0 ? 0 : _catRows.Max(c => c.MinDetections) + 1);
            _catRows.Add(new VerdictCategory { MinDetections = next, Name = "Yeni", ColorHex = "#888888" });
        }, accent: true));
        buttons.Controls.Add(ThemeManager.MakeButton("Renk seç…", (_, _) =>
        {
            if (_catGrid.CurrentRow?.DataBoundItem is not VerdictCategory c) return;
            using var dlg = new ColorDialog { Color = c.Color, FullOpen = true };
            if (dlg.ShowDialog() == DialogResult.OK) { c.ColorHex = "#" + dlg.Color.R.ToString("X2") + dlg.Color.G.ToString("X2") + dlg.Color.B.ToString("X2"); _catGrid.Invalidate(); }
        }));
        buttons.Controls.Add(ThemeManager.MakeButton("Sil", (_, _) => { if (_catGrid.CurrentRow?.DataBoundItem is VerdictCategory c) _catRows!.Remove(c); }));
        buttons.Controls.Add(ThemeManager.MakeButton("Kaydet", (_, _) => { VerdictCategories.Save(_catRows!); RefreshCats(); Theme.ApplyFromSettings(); NativeMessageBox.Info("Kategoriler kaydedildi."); }));
        buttons.Controls.Add(ThemeManager.MakeButton("Varsayılan", (_, _) => { VerdictCategories.Save(VerdictCategories.Defaults()); RefreshCats(); Theme.ApplyFromSettings(); }));

        body.Controls.Add(buttons);
        body.Controls.Add(_catGrid);
        body.Controls.Add(ThemeManager.MakeLabel("Eşikler benzersiz olmalı. Örn: 0→TEMİZ, 2→ŞÜPHELİ, 3→VİRÜS.", subtle: true));
        return card;
    }

    void RefreshCats()
    {
        _catRows = new System.ComponentModel.BindingList<VerdictCategory>(
            VerdictCategories.All.Select(c => new VerdictCategory { MinDetections = c.MinDetections, Name = c.Name, ColorHex = c.ColorHex }).ToList());
        if (_catGrid != null) _catGrid.DataSource = _catRows;
    }

    Panel BuildScanCard()
    {
        var card = Card("Tarama", 250, out var body);

        var concurrency = LabeledNumeric("Eşzamanlı tarama:", Settings.MaxConcurrentScans, 1, 16,
            v => { Settings.MaxConcurrentScans.Value = v; SettingsManager.SaveSettings(); });
        var cache = new CheckBox { Text = "Yerel hash önbelleği kullan (kota tasarrufu)", AutoSize = true, Checked = Settings.UseLocalHashCache };
        cache.CheckedChanged += (_, _) => { Settings.UseLocalHashCache.Value = cache.Checked; SettingsManager.SaveSettings(); };
        var cacheDays = LabeledNumeric("Önbellek geçerlilik (gün):", Settings.HashCacheDays, 0, 365,
            v => { Settings.HashCacheDays.Value = v; SettingsManager.SaveSettings(); });
        var skipSafe = new CheckBox { Text = "Taramada güvenli türleri atla", AutoSize = true, Checked = Settings.SkipSafeExtensionsOnScan };
        skipSafe.CheckedChanged += (_, _) => { Settings.SkipSafeExtensionsOnScan.Value = skipSafe.Checked; SettingsManager.SaveSettings(); };

        var lbl = ThemeManager.MakeLabel("Güvenli uzantılar (; ile ayır):");
        var exts = new TextBox { Dock = DockStyle.Top, Text = Settings.SafeExtensions, Height = 24 };
        var save = ThemeManager.MakeButton("Uzantıları kaydet", (_, _) => { Settings.SafeExtensions.Value = exts.Text.Trim(); SettingsManager.SaveSettings(); });

        body.Controls.Add(exts);
        body.Controls.Add(lbl);
        body.Controls.Add(save);
        body.Controls.Add(skipSafe);
        body.Controls.Add(cacheDays);
        body.Controls.Add(cache);
        body.Controls.Add(concurrency);
        return card;
    }

    Panel BuildGeneralCard()
    {
        var card = Card("Genel", 315, out var body);

        var themeRow = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top };
        themeRow.Controls.Add(ThemeManager.MakeLabel("Tema:"));
        var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 160 };
        combo.Items.AddRange(["Sistemi izle", "Koyu", "Açık"]);
        combo.SelectedIndex = Settings.FollowWindowsTheme ? 0 : (string.Equals(Settings.Theme.Value, "Light", StringComparison.OrdinalIgnoreCase) ? 2 : 1);
        combo.SelectedIndexChanged += (_, _) =>
        {
            if (combo.SelectedIndex == 0) Theme.SetTheme("Dark", follow: true);
            else Theme.SetTheme(combo.SelectedIndex == 2 ? "Light" : "Dark", follow: false);
        };
        themeRow.Controls.Add(combo);

        var tray = new CheckBox { Text = "Kapatınca sistem tepsisine küçült", AutoSize = true, Checked = Settings.MinimizeToTray };
        tray.CheckedChanged += (_, _) => { Settings.MinimizeToTray.Value = tray.Checked; SettingsManager.SaveSettings(); };
        var notify = new CheckBox { Text = "Tehdit bulununca bildirim göster", AutoSize = true, Checked = Settings.NotifyOnThreat };
        notify.CheckedChanged += (_, _) => { Settings.NotifyOnThreat.Value = notify.Checked; SettingsManager.SaveSettings(); };
        var logging = new CheckBox { Text = "Loglama açık", AutoSize = true, Checked = LoggerHost.IsEnabled };
        logging.CheckedChanged += (_, _) => LoggerHost.SetEnabled(logging.Checked);

        var startup = new CheckBox { Text = "Windows ile başlat (arka planda, tepside)", AutoSize = true, Checked = StartupManager.IsEnabled() };
        startup.CheckedChanged += (_, _) => StartupManager.SetEnabled(startup.Checked);

        var resume = new CheckBox { Text = "Açılışta yarım kalan taramayı sor", AutoSize = true, Checked = Settings.ResumeInterruptedScans };
        resume.CheckedChanged += (_, _) => { Settings.ResumeInterruptedScans.Value = resume.Checked; SettingsManager.SaveSettings(); };

        var autoResume = new CheckBox { Text = "Açılışta yarım kalan taramayı SORMADAN devam et", AutoSize = true, Checked = Settings.AutoResumeScans };
        autoResume.CheckedChanged += (_, _) => { Settings.AutoResumeScans.Value = autoResume.Checked; SettingsManager.SaveSettings(); };

        body.Controls.Add(themeRow);
        body.Controls.Add(startup);
        body.Controls.Add(resume);
        body.Controls.Add(autoResume);
        body.Controls.Add(tray);
        body.Controls.Add(notify);
        body.Controls.Add(logging);
        return card;
    }

    Panel BuildConfirmGatesCard()
    {
        var gates = ConfirmGateManager.All.ToList();
        var card = Card("Onay Soruları (bir daha sorma)", 70 + gates.Count * 30, out var body);
        body.Controls.Add(ThemeManager.MakeLabel("'Bir daha sorma' dediğin onaylar burada görünür; istersen tekrar sormaya açabilirsin.", subtle: true));
        foreach (var gate in gates)
        {
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top };
            var lbl = ThemeManager.MakeLabel("");
            var btn = ThemeManager.MakeButton("Tekrar sor", null);
            void Refresh()
            {
                lbl.Text = gate.Title + (gate.Suppressed ? $"  —  KAPALI (yanıt: {(gate.RememberedAnswer ? "Evet" : "Hayır")})" : "  —  soruluyor");
                btn.Enabled = gate.Suppressed;
            }
            btn.Click += (_, _) => { gate.ResetSuppression(); Refresh(); };
            Refresh();
            row.Controls.Add(lbl);
            row.Controls.Add(btn);
            body.Controls.Add(row);
        }
        return card;
    }

    Panel BuildAboutCard()
    {
        var card = Card("Hakkında", 110, out var body);
        body.Controls.Add(ThemeManager.MakeLabel($"{AppConstants.AppTitle} v{AppConstants.Version}", subtle: true));
        var link = new LinkLabel { Text = "VirusTotal API anahtarı al (virustotal.com)", AutoSize = true };
        link.LinkClicked += (_, _) => OpenUrlInBrowser("https://www.virustotal.com/gui/my-apikey");
        body.Controls.Add(link);
        body.Controls.Add(ThemeManager.MakeLabel("Ayar dosyası: " + ConfigPathResolver.ConfigPath, subtle: true));
        return card;
    }

    // ---- key actions ----

    void AddKey()
    {
        using var dlg = new ApiKeyDialog();
        if (dlg.ShowDialog(this) == DialogResult.OK)
            AppServices.Vault.Add(dlg.KeyLabel, dlg.KeyValue);
    }

    void EditKey()
    {
        var id = SelectedKeyId();
        if (id == null) return;
        var entry = AppServices.Vault.Keys.FirstOrDefault(k => k.Id == id);
        if (entry == null) return;
        using var dlg = new ApiKeyDialog(entry.Label, entry.Key);
        if (dlg.ShowDialog(this) == DialogResult.OK)
            AppServices.Vault.UpdateMeta(id, dlg.KeyLabel, dlg.KeyValue);
    }

    void RemoveKey()
    {
        var id = SelectedKeyId();
        if (id == null) return;
        if (NativeMessageBox.Confirm("Bu anahtar silinsin mi?")) AppServices.Vault.Remove(id);
    }

    string? SelectedKeyId() => (_keysGrid.CurrentRow?.DataBoundItem as KeyRow)?.Id;

    void RefreshKeys()
    {
        var now = DateTime.UtcNow;
        var rows = AppServices.Vault.Keys.Select(k => new KeyRow
        {
            Id = k.Id,
            Label = string.IsNullOrWhiteSpace(k.Label) ? "Key" : k.Label,
            Anahtar = k.Masked,
            Durum = k.Disabled ? "Devre dışı" : k.IsExhausted(now) ? "Dolu" : "Aktif",
        }).ToList();
        _keysGrid.DataSource = rows;
    }

    void InstallMenu()
    {
        if (!NativeMessageBox.Confirm(
            "VirusTotalScanner kendisini Windows sağ tuş menüsüne (tüm kullanıcılar) ekleyecek.\n" +
            "Yönetici izni (UAC) istenecek.\n\nDevam edilsin mi?",
            "İzin"))
            return;
        RunMenuOp(() => ContextMenuInstaller.Install(Settings.ContextMenuExcludeSafe, out var e),
            "Sağ tuş menüsüne eklendi.\nWindows 11'de 'Daha fazla seçenek göster' altında görünür.");
    }

    /// <summary>Runs an elevation-capable menu op off the UI thread, then refreshes status.</summary>
    void RunMenuOp(Func<bool> op, string okMsg)
    {
        _ = Task.Run(() =>
        {
            bool ok = op();
            SafeUi(() =>
            {
                RefreshMenuStatus();
                if (ok) NativeMessageBox.Info(okMsg);
                else NativeMessageBox.Warn("İşlem tamamlanamadı (yönetici izni gerekebilir).");
            });
        });
    }

    void RefreshMenuStatus()
    {
        var state = ContextMenuInstaller.Verify();
        _menuStatus.Text = "Durum: " + ContextMenuInstaller.Describe(state);
        _menuStatus.ForeColor = state switch
        {
            MenuState.Ok => Theme.Current.Success,
            MenuState.Stale => Theme.Current.Warning,
            MenuState.Missing => Theme.Current.SubtleText,
            _ => Theme.Current.Danger,
        };
    }

    // ---- ui helpers ----

    Panel Card(string title, int height, out FlowLayoutPanel body)
    {
        var card = ThemeManager.MakeCard();
        card.Height = height;
        card.Width = 700;

        var titleLbl = ThemeManager.MakeTitle(title);
        titleLbl.Dock = DockStyle.Top;

        body = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = false, BackColor = Color.Transparent };
        // Add controls bottom-up because Dock=Top stacks in reverse insertion order.
        card.Controls.Add(body);
        card.Controls.Add(titleLbl);
        return card;
    }

    Control LabeledNumeric(string label, int value, int min, int max, Action<int> onChange)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Dock = DockStyle.Top };
        row.Controls.Add(ThemeManager.MakeLabel(label));
        var nud = new NumericUpDown { Minimum = min, Maximum = max, Value = Math.Clamp(value, min, max), Width = 70 };
        nud.ValueChanged += (_, _) => onChange((int)nud.Value);
        row.Controls.Add(nud);
        return row;
    }

    void SafeUi(Action a) { try { if (IsHandleCreated) BeginInvoke(a); else a(); } catch (Exception ex) { Log("UI dispatch failed: " + ex.Message, LogLevel.Warning); } }

    public void ApplyTheme()
    {
        ThemeManager.StyleGrid(_keysGrid);
        RefreshMenuStatus();
    }
}
