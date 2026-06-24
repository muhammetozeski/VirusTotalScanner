using System.Drawing;

namespace VirusTotalScanner;

/// <summary>
/// Right-hand detail pane: verdict banner, file meta, hashes (with copy), detection stats,
/// detection-ratio bar, the engine table, and a link to the VirusTotal report.
/// </summary>
internal sealed class ScanDetailControl : UserControl
{
    readonly VerdictHeroPanel _hero = new();
    readonly FlowLayoutPanel _actionStrip = new() { AutoSize = true, WrapContents = false, Dock = DockStyle.Fill, Margin = new Padding(0, 0, 0, 6), Visible = false };
    readonly Label _meta = new();

    /// <summary>The user chose the recommended action from the detail pane's guided strip.</summary>
    public event Action<ScanItem>? QuarantineRequested, RescanRequested, MarkCleanRequested;

    // Collapsible "what this does to my PC" digest row (filled on demand by the behaviour button).
    readonly FlowLayoutPanel _behaviourPanel = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Visible = false, Margin = new Padding(0, 4, 0, 4) };
    readonly Label _stats = new();
    readonly Panel _ratioBar = new();
    readonly Label _md5 = new();
    readonly Label _sha = new();
    readonly LinkLabel _link = new();
    readonly CheckBox _showAll = new();
    readonly CheckBox _majorOnly = new() { Text = "Yalnızca büyük motorlar", AutoSize = true, Margin = new Padding(10, 4, 0, 0) };
    readonly DataGridView _engines = new();
    readonly Label _empty = new();

    ScanItem? _item;

    public ScanDetailControl()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(12);

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 9, BackColor = Color.Transparent };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 104)); // verdict hero card
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // guided action strip
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // meta
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // hashes
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // stats
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // ratio
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // toggle + link
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); // behaviour digest (collapsible)
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // grid

        _meta.AutoSize = true; _meta.MaximumSize = new Size(2000, 0);
        _stats.AutoSize = true; _stats.Font = new Font("Segoe UI", 9.5f, FontStyle.Bold);

        _ratioBar.Height = 14; _ratioBar.Dock = DockStyle.Fill; _ratioBar.Margin = new Padding(0, 4, 0, 8);
        _ratioBar.Paint += RatioBar_Paint;

        var hashPanel = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 6) };
        hashPanel.Controls.Add(HashRow("MD5", _md5, () => _item?.Md5));
        hashPanel.Controls.Add(HashRow("SHA-256", _sha, () => _item?.Sha256));

        var togglePanel = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Margin = new Padding(0, 4, 0, 4) };
        _showAll.Text = Strings.ShowAllEngines;
        _showAll.AutoSize = true;
        _showAll.Checked = true; // default: show every engine's result, not just detections
        _showAll.CheckedChanged += (_, _) => Populate();
        _majorOnly.CheckedChanged += (_, _) => Populate();
        _link.Text = Strings.OpenVtReport;
        _link.AutoSize = true;
        _link.Margin = new Padding(16, 3, 0, 0);
        _link.LinkClicked += (_, _) => { if (_item?.Report != null) OpenUrlInBrowser(_item.Report.ReportUrl); };
        var commentsBtn = new Button { Text = Strings.BtnComments, AutoSize = true, Margin = new Padding(16, 0, 0, 0) };
        commentsBtn.Click += async (_, _) =>
        {
            string? sha = _item?.Sha256;
            if (string.IsNullOrWhiteSpace(sha)) return;
            if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable)) { NativeMessageBox.Warn(Strings.CommentsNeedKeyless); return; }
            commentsBtn.Enabled = false;
            string old = commentsBtn.Text;
            commentsBtn.Text = Strings.CommentsFetching;
            try
            {
                var comments = await GuiScrapeService.FetchCommentsAsync(sha);
                if (comments.Count == 0) { NativeMessageBox.Info(Strings.CommentsNone); return; }
                var sb = new System.Text.StringBuilder();
                foreach (var c in comments.Take(20))
                {
                    sb.AppendLine($"[{c.Date:yyyy-MM-dd}] {c.Text?.Trim()}");
                    if (c.Tags.Count > 0) sb.AppendLine("   #" + string.Join(" #", c.Tags));
                    sb.AppendLine();
                }
                NativeMessageBox.Info(sb.ToString());
            }
            catch (Exception ex) { NativeMessageBox.Error(Strings.CommentsFailedPrefix + ex.Message); }
            finally { commentsBtn.Enabled = true; commentsBtn.Text = old; }
        };
        ThemeManager.StyleButton(commentsBtn);

        var behaviourBtn = new Button { Text = Strings.BtnBehaviour, AutoSize = true, Margin = new Padding(8, 0, 0, 0) };
        behaviourBtn.Click += async (_, _) =>
        {
            if (_behaviourPanel.Visible) { _behaviourPanel.Visible = false; return; } // toggle collapse
            string? sha = _item?.Sha256;
            if (string.IsNullOrWhiteSpace(sha)) return;

            var cachedDigest = BehaviourDigestCache.TryGet(sha);
            if (cachedDigest != null) { RenderBehaviour(cachedDigest); return; } // never re-scrape

            if (!(Settings.KeylessGuiLookup && GuiScrapeService.IsRuntimeAvailable)) { NativeMessageBox.Warn(Strings.BehaviourNeedKeyless); return; }
            behaviourBtn.Enabled = false;
            string old = behaviourBtn.Text;
            behaviourBtn.Text = Strings.BehaviourFetching;
            try
            {
                var b = await GuiScrapeService.FetchBehaviourAsync(sha);
                // Persist + correlate network IOCs across files (shared C2 = same campaign).
                var iocs = b.Network.Select(x => { int sp = x.IndexOf(' '); return sp >= 0 ? x[(sp + 1)..].Trim() : x; }).ToList();
                IocStore.Record(sha, _item?.FilePath, _item?.Report?.IsMalicious == true, iocs);

                var digest = BehaviourDigestBuilder.Build(b);
                var conns = IocStore.Connections(sha, iocs);
                if (conns.Count > 0)
                    digest.Lines.Add(new DigestLine(conns.Any(c => c.Malicious) ? "🔴" : "🔗",
                        $"{conns.Count} taranmış dosyayla ortak ağ göstergesi paylaşıyor (aynı kampanya olabilir)", conns.Any(c => c.Malicious)));
                BehaviourDigestCache.Put(sha, digest);
                RenderBehaviour(digest);
            }
            catch (Exception ex) { NativeMessageBox.Error("Davranış alınamadı: " + ex.Message); }
            finally { behaviourBtn.Enabled = true; behaviourBtn.Text = old; }
        };
        ThemeManager.StyleButton(behaviourBtn);

        togglePanel.Controls.Add(_showAll);
        togglePanel.Controls.Add(_majorOnly);
        togglePanel.Controls.Add(_link);
        togglePanel.Controls.Add(commentsBtn);
        togglePanel.Controls.Add(behaviourBtn);

        ConfigureEnginesGrid();
        _engines.Dock = DockStyle.Fill;

        _empty.Text = Strings.DetailEmptyHint;
        _empty.Dock = DockStyle.Fill;
        _empty.TextAlign = ContentAlignment.MiddleCenter;
        _empty.Tag = "subtle";

        root.Controls.Add(_hero, 0, 0);
        root.Controls.Add(_actionStrip, 0, 1);
        root.Controls.Add(_meta, 0, 2);
        root.Controls.Add(hashPanel, 0, 3);
        root.Controls.Add(_stats, 0, 4);
        root.Controls.Add(_ratioBar, 0, 5);
        root.Controls.Add(togglePanel, 0, 6);
        root.Controls.Add(_behaviourPanel, 0, 7);
        root.Controls.Add(_engines, 0, 8);

        Controls.Add(root);
        Controls.Add(_empty);
        _empty.BringToFront();
        Show(null); // start in the empty state
    }

    Control HashRow(string label, Label valueLabel, Func<string?> getter)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 2, 0, 2) };
        var l = new Label { Text = label + ":", AutoSize = true, Width = 70, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Margin = new Padding(0, 4, 6, 0) };
        valueLabel.AutoSize = true;
        valueLabel.Font = new Font("Consolas", 9f);
        valueLabel.Margin = new Padding(0, 4, 6, 0);
        var copy = new Button { Text = Strings.BtnCopy, AutoSize = true, Margin = new Padding(0) };
        copy.Click += (_, _) => { var v = getter(); if (!string.IsNullOrEmpty(v)) { try { Clipboard.SetText(v); } catch (Exception ex) { Log("Clipboard copy failed: " + ex.Message, LogLevel.Warning); } } };
        ThemeManager.StyleButton(copy);
        row.Controls.Add(l);
        row.Controls.Add(valueLabel);
        row.Controls.Add(copy);
        return row;
    }

    void ConfigureEnginesGrid()
    {
        _engines.AutoGenerateColumns = false;
        _engines.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColEngine, DataPropertyName = nameof(VtEngineResult.EngineName), Width = 160 });
        _engines.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColCategory, DataPropertyName = nameof(VtEngineResult.Category), Width = 110 });
        _engines.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColResult, DataPropertyName = nameof(VtEngineResult.Result), AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _engines.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = Strings.ColVersion, DataPropertyName = nameof(VtEngineResult.EngineVersion), Width = 110 });
        _engines.CellFormatting += Engines_CellFormatting;

        // Plain-language tooltips decoding AV jargon on the Category / Result columns.
        _engines.ShowCellToolTips = true;
        _engines.CellToolTipTextNeeded += (_, e) =>
        {
            if (e.RowIndex < 0 || e.ColumnIndex < 0) return;
            string prop = _engines.Columns[e.ColumnIndex].DataPropertyName;
            string? val = _engines.Rows[e.RowIndex].Cells[e.ColumnIndex].Value?.ToString();
            if (prop == nameof(VtEngineResult.Category)) e.ToolTipText = JargonGlossary.Category(val);
            else if (prop == nameof(VtEngineResult.Result)) e.ToolTipText = JargonGlossary.Result(val);
        };

        // Right-click an engine row: copy the engine name, its result, or search the result online.
        var menu = new ContextMenuStrip();
        menu.Items.Add(Strings.MenuCopyEngineName, null, (_, _) => CopyEngine(r => r.EngineName));
        menu.Items.Add("📋  Sonucu kopyala", null, (_, _) => CopyEngine(r => r.Result));
        menu.Items.Add("🔎  Sonucu internette ara", null, (_, _) => SearchEngineResult());
        _engines.ContextMenuStrip = menu;

        ThemeManager.StyleGrid(_engines);
    }

    VtEngineResult? SelectedEngine() => _engines.CurrentRow?.DataBoundItem as VtEngineResult;

    void CopyEngine(Func<VtEngineResult, string?> pick)
    {
        var v = SelectedEngine();
        if (v == null) return;
        string? s = pick(v);
        if (!string.IsNullOrEmpty(s)) { try { Clipboard.SetText(s); } catch (Exception ex) { Log("Clipboard copy failed: " + ex.Message, LogLevel.Warning); } }
    }

    void SearchEngineResult()
    {
        var v = SelectedEngine();
        if (v?.Result is { Length: > 0 } res)
            OpenUrlInBrowser("https://www.google.com/search?q=" + Uri.EscapeDataString(res + " malware"));
    }

    /// <summary>"When did THIS machine first see it" — the local arrival anchor from the hash cache, which
    /// VT's global FirstSeen can't answer ("the world saw it 2y ago, but it landed here yesterday").</summary>
    internal static string? LocalFirstSeenLine(ScanItem item)
    {
        if (AppServices.Cache.LocalFirstSeen(item.Md5 ?? item.Report?.Md5) is not { } utc) return null;
        int days = Math.Max(0, (int)(DateTime.UtcNow - utc).TotalDays);
        string ago = days == 0 ? "bugün" : $"{days} gün önce";
        return $"💻 Bu makinede ilk görülme: {utc.ToLocalTime():yyyy-MM-dd} ({ago})";
    }

    static bool IsStaleSig(VtEngineResult r)
    {
        int days = Settings.StaleSignatureDays;
        return days > 0 && r.UpdatedUtc is { } u && u < DateTime.UtcNow.AddDays(-days);
    }

    void Engines_CellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
    {
        if (_engines.Rows[e.RowIndex].DataBoundItem is not VtEngineResult r) return;
        bool major = MajorEngines.IsMajor(r.EngineName);
        bool stale = r.IsDetection && IsStaleSig(r);

        if (r.IsDetection)
        {
            // A stale-signature detection is greyed (less alarming) vs a fresh red hit.
            e.CellStyle!.ForeColor = stale ? Color.FromArgb(150, 150, 150) : Theme.Current.Danger;
            e.CellStyle.Font = new Font(_engines.Font, FontStyle.Bold);
        }
        // Engine-name column: ★ + bold for the engines that matter, 🕒 for stale-signature detections.
        if (e.ColumnIndex == 0 && e.Value is string name)
        {
            if (stale) e.Value = "🕒 " + name;
            else if (major) e.Value = "★ " + name;
            if (major) e.CellStyle!.Font = new Font(_engines.Font, FontStyle.Bold);
        }
    }

    public void Show(ScanItem? item)
    {
        _item = item;
        Populate();
    }

    void Populate()
    {
        var item = _item;
        bool trustedSkip = item is { Status: ScanStatus.TrustedSkipped };
        var report = item?.Report;
        bool hasReport = report != null;
        _behaviourPanel.Visible = false; // collapse last item's digest; the behaviour button re-opens it

        _empty.BackColor = Theme.Current.Background; // opaque so it covers the detail rows
        if (!hasReport && !trustedSkip)
        {
            _empty.Visible = true;
            _empty.BringToFront();
            _actionStrip.Visible = false;
            _engines.DataSource = null;
            return;
        }
        _empty.Visible = false;

        if (trustedSkip)
        {
            _hero.Set(Strings.StatusSignedShort, "VirusTotal taraması atlandı",
                RecommendationService.Build(item!).Headline, "✓", Theme.Current.Accent);
            _actionStrip.Visible = false;
            _meta.Text =
                $"{Strings.DetailLblFile}{item!.FileName}\n" +
                $"{Strings.DetailLblStatus}{item.SkipReason ?? Strings.StatusSignedShort}" +
                (item.Publisher != null ? $"\n{Strings.DetailLblPublisher}{item.Publisher}" : "") +
                (ZoneIdentifier.Read(item.FilePath)?.Summary is { } z ? $"\n{z}" : "") +
                (OverlayDetector.OverlayBytes(item.FilePath) is var ov && ov > 65536
                    ? "\n" + string.Format(Strings.OverlayNoteFormat, FormatBytes(ov)) : "") +
                Strings.SignedExplain;
            _md5.Text = item.Md5 ?? "-";
            _sha.Text = item.Sha256 ?? "-";
            _stats.Text = "";
            _ratioBar.Invalidate();
            _engines.DataSource = null;
            return;
        }

        string verdict = report!.Verdict;

        // Provenance line: where this verdict came from.
        string provenance = item!.FromCache ? Strings.ProvenanceCache : Strings.ProvenanceScan;

        var reco = RecommendationService.Build(item);
        string heroGlyph = report.IsMalicious ? "✕" : report.DetectionCount > 0 ? "!" : report.TotalEngines == 0 ? "?" : "✓";
        _hero.Set(verdict, string.Format(Strings.BannerVerdictFormat, verdict, report.DetectionCount, report.TotalEngines),
            reco.Headline, heroGlyph, Theme.VerdictColor(verdict));
        BuildActionStrip(reco);
        _meta.Text =
            $"👉 {reco.Emoji} {reco.Headline}\n{reco.Rationale}\n\n" +
            $"{Strings.DetailLblName}{report.MeaningfulName ?? item.FileName}\n" +
            $"{Strings.DetailLblType}{report.TypeDescription ?? "?"}\n" +
            $"{Strings.DetailLblSize}{(report.Size > 0 ? FormatBytes(report.Size) : item.SizeText)}" +
            (report.Reputation != 0 ? $"\n{Strings.DetailLblReputation}{report.Reputation}" : "") +
            (report.FirstSeenText != null ? $"\n{report.FirstSeenText}" : "") +
            (LocalFirstSeenLine(item) is { } lfs ? $"\n{lfs}" : "") +
            (report.ConsensusText != null ? $"\n{report.ConsensusText}" : "") +
            (report.ConfidenceText != null ? $"\n{report.ConfidenceText}" : "") +
            (item.SignatureSoftened ? $"\n🔓 Geçerli imza nedeniyle muhtemel yanlış pozitif: {item.Trust?.Publisher ?? item.Publisher ?? "imzalı"} — ‘Temiz olarak işaretle’ ile onayla" : "") +
            (report.StaleText != null ? $"\n{report.StaleText}" : "") +
            (report.CommunityRulesText != null ? $"\n{report.CommunityRulesText}" : "") +
            (report.FamilyLabel != null ? $"\n{report.FamilyLabel}" : "") +
            (report.CapabilitySummary != null ? $"\n{report.CapabilitySummary}" : "") +
            (Settings.ShowCommunityVotes && report.VotesText != null ? $"\n{report.VotesText}" : "") +
            (ZoneIdentifier.Read(item.FilePath)?.Summary is { } zone ? $"\n{zone}" : "") +
            (PeIdentityService.IdentitySummary(item.FilePath, TrustService.Evaluate(item.FilePath)) is { } pe ? $"\n{pe}" : "") +
            $"\n{provenance}";

        _md5.Text = report.Md5 ?? item.Md5 ?? "-";
        _sha.Text = report.Sha256 ?? item.Sha256 ?? "-";

        _stats.Text = string.Format(Strings.StatsFormat, report.Malicious, report.Suspicious, report.Harmless, report.Undetected, report.Timeout);
        _ratioBar.Invalidate();

        var list = _showAll.Checked ? report.Engines : report.Detections.ToList();
        if (_majorOnly.Checked) list = list.Where(x => MajorEngines.IsMajor(x.EngineName)).ToList();
        _engines.DataSource = null;
        _engines.DataSource = new List<VtEngineResult>(list);
        // Cached entries keep only the summary (no per-engine list) to stay small.
        if (report.Engines.Count == 0 && report.TotalEngines > 0)
            _stats.Text += Strings.StatsCacheNote;
    }

    /// <summary>Guided next step: surface the recommended action inline (primary highlighted) so the
    /// user is led to one obvious safe move at the alarming moment instead of hunting the right-click menu.</summary>
    void RenderBehaviour(BehaviourDigest d)
    {
        _behaviourPanel.Controls.Clear();
        _behaviourPanel.Controls.Add(new Label { Text = "🧪 Bu dosya çalışırsa PC'ne ne yapar:", AutoSize = true, Font = new Font("Segoe UI", 9.5f, FontStyle.Bold), Margin = new Padding(0, 2, 0, 4) });
        foreach (var line in d.Lines)
        {
            bool hasDetails = line.Details is { Count: > 0 };
            var lbl = new Label { Text = line.Icon + "  " + line.Text + (hasDetails ? "   ▸" : ""), AutoSize = true, Margin = new Padding(10, 1, 0, 1) };
            if (line.Alarm) { lbl.ForeColor = Theme.Current.Danger; lbl.Font = new Font("Segoe UI", 9f, FontStyle.Bold); }
            _behaviourPanel.Controls.Add(lbl);

            if (hasDetails)
            {
                bool isNet = line.Icon == "🌐";
                var details = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, Visible = false, Margin = new Padding(28, 0, 0, 4) };
                foreach (var item in line.Details!) details.Controls.Add(BuildIocRow(item, isNet));
                _behaviourPanel.Controls.Add(details);
                lbl.Cursor = Cursors.Hand;
                string baseText = line.Icon + "  " + line.Text;
                lbl.Click += (_, _) => { details.Visible = !details.Visible; lbl.Text = baseText + (details.Visible ? "   ▾" : "   ▸"); };
            }
        }
        _behaviourPanel.Visible = true;
    }

    Control BuildIocRow(string item, bool isNetwork)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 1) };
        row.Controls.Add(new Label { Text = item, AutoSize = true, Tag = "subtle", Margin = new Padding(0, 4, 8, 0) });
        var copy = new Button { Text = Strings.BtnCopy, AutoSize = true, Margin = new Padding(0) };
        copy.Click += (_, _) => { try { Clipboard.SetText(item); } catch (Exception ex) { Log("Clipboard copy failed: " + ex.Message, LogLevel.Warning); } };
        ThemeManager.StyleButton(copy);
        row.Controls.Add(copy);
        if (isNetwork)
        {
            int sp = item.IndexOf(' ');
            string host = (sp >= 0 ? item[(sp + 1)..] : item).Trim();
            if (host.Length > 0)
            {
                var search = new LinkLabel { Text = "ara ↗", AutoSize = true, Margin = new Padding(8, 4, 0, 0) };
                search.LinkClicked += (_, _) => OpenUrlInBrowser("https://www.virustotal.com/gui/search/" + Uri.EscapeDataString(host));
                row.Controls.Add(search);
            }
        }
        return row;
    }

    void BuildActionStrip(RecommendationService.Reco reco)
    {
        _actionStrip.Controls.Clear();
        if (reco.Level == RecommendationService.Level.Keep) { _actionStrip.Visible = false; return; }

        bool remove = reco.Level == RecommendationService.Level.Remove;
        var quar = ThemeManager.MakeButton("🛡  Karantinaya al", (_, _) => { if (_item != null) QuarantineRequested?.Invoke(_item); }, accent: remove);
        var rescan = ThemeManager.MakeButton("🔄  Önce yeniden tara", (_, _) => { if (_item != null) RescanRequested?.Invoke(_item); }, accent: !remove);
        var vt = ThemeManager.MakeButton("🔗  VT raporu", (_, _) => { if (_item?.Report != null) OpenUrlInBrowser(_item.Report.ReportUrl); });
        if (remove) { _actionStrip.Controls.Add(quar); _actionStrip.Controls.Add(rescan); }
        else { _actionStrip.Controls.Add(rescan); _actionStrip.Controls.Add(quar); }
        _actionStrip.Controls.Add(vt);
        // False-positive escape hatch: vouch the file is clean so it stops being re-flagged every scan.
        var markClean = ThemeManager.MakeButton("✓  Temiz olarak işaretle", (_, _) => { if (_item != null) MarkCleanRequested?.Invoke(_item); });
        _actionStrip.Controls.Add(markClean);
        _actionStrip.Visible = true;
    }

    void RatioBar_Paint(object? sender, PaintEventArgs e)
    {
        var report = _item?.Report;
        var p = Theme.Current;
        var g = e.Graphics;
        var rect = _ratioBar.ClientRectangle;
        using (var bg = new SolidBrush(p.Surface)) g.FillRectangle(bg, rect);
        if (report == null || report.TotalEngines == 0) return;

        int total = report.TotalEngines;
        float x = 0;
        void Seg(int count, Color c)
        {
            if (count <= 0) return;
            float w = (float)count / total * rect.Width;
            using var b = new SolidBrush(c);
            g.FillRectangle(b, x, 0, w, rect.Height);
            x += w;
        }
        Seg(report.Malicious, p.Danger);
        Seg(report.Suspicious, p.Warning);
        Seg(report.Harmless, p.Success);
        Seg(report.Undetected, p.Border);
    }

    public void ApplyTheme()
    {
        ThemeManager.StyleGrid(_engines);
        Populate();
    }
}
