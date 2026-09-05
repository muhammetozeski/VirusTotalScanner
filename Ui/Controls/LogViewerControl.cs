using System.Drawing;

namespace VirusTotalScanner;

/// <summary>"Loglar" tab: live log stream + on/off toggle, clear, copy-all, open folder.</summary>
internal sealed class LogViewerControl : UserControl
{
    readonly RichTextBox _box = new() { AccessibleName = TooltipCatalog.LogBox };
    readonly CheckBox _enable = new();
    readonly ToolTip _tips = new() { AutoPopDelay = 32000, InitialDelay = 350, ReshowDelay = 100 };
    int _lines;
    const int MaxLines = 3000;

    /// <summary>Lines that have arrived since the last repaint, oldest first. Held under its own lock
    /// because log lines arrive from every scan thread at once.</summary>
    readonly Queue<string> _incoming = new();
    readonly object _incomingLock = new();
    readonly System.Windows.Forms.Timer _drain = new() { Interval = 250 };
    /// <summary>Never hold more than one screenful-ish of backlog: during a disk sweep the log runs at
    /// thousands of lines a second and nobody can read a tick's worth anyway.</summary>
    const int MaxPendingLines = 400;

    public LogViewerControl()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(8);

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        _enable.Text = Strings.LoggingLabel;
        _enable.AutoSize = true;
        _enable.Checked = LoggerHost.IsEnabled;
        _enable.Margin = new Padding(6, 8, 12, 4);
        _enable.CheckedChanged += (_, _) => LoggerHost.SetEnabled(_enable.Checked);
        bar.Controls.Add(_enable);
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnLogClear, (_, _) => { _box.Clear(); _lines = 0; Logger.ClearAllLogs(); }));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnLogCopyAll, (_, _) => { try { Clipboard.SetText(Logger.GetAllLogsText()); } catch (Exception ex) { Log("Clipboard copy failed: " + ex.Message, LogLevel.Warning); } }));
        bar.Controls.Add(ThemeManager.MakeButton(Strings.BtnLogOpenFolder, (_, _) =>
        {
            try { Directory.CreateDirectory(ConfigPathResolver.LogsFolder); OpenWithDefaultProgram(ConfigPathResolver.LogsFolder); } catch { }
        }));

        _box.Dock = DockStyle.Fill;
        _box.ReadOnly = true;
        _box.Multiline = true;
        _box.WordWrap = false;
        _box.ScrollBars = RichTextBoxScrollBars.Both;
        _box.Font = new Font("Consolas", 9f);
        _box.BorderStyle = BorderStyle.None;

        Controls.Add(_box);
        Controls.Add(bar);
        TooltipCatalog.Apply(_tips, this);

        LoggerHost.OnLogLine += OnLogLine;
        _drain.Tick += (_, _) => Drain();
        _drain.Start();
    }

    /// <summary>
    /// Buffers a line for the next repaint. It used to BeginInvoke straight onto the UI thread, which
    /// is fine at a few lines a second and fatal at the couple of thousand a disk sweep produces: the
    /// message pump filled with log appends and the window stopped answering. Now the lines pile up
    /// here and one timer tick writes whatever arrived.
    /// </summary>
    void OnLogLine(string line)
    {
        lock (_incomingLock)
        {
            _incoming.Enqueue(line);
            while (_incoming.Count > MaxPendingLines) _incoming.Dequeue();
        }
    }

    /// <summary>Writes the lines buffered since the last tick in one append. Skipped entirely while the
    /// tab is not on screen — the complete log is on disk either way.</summary>
    void Drain()
    {
        if (!IsHandleCreated || !Visible) return;

        string[] batch;
        lock (_incomingLock)
        {
            if (_incoming.Count == 0) return;
            batch = _incoming.ToArray();
            _incoming.Clear();
        }

        try
        {
            if (_lines >= MaxLines) { _box.Clear(); _lines = 0; }

            var sb = new System.Text.StringBuilder();
            foreach (var line in batch) sb.Append(line.TrimEnd()).Append(Environment.NewLine);
            _box.AppendText(sb.ToString());
            _lines += batch.Length;

            _box.SelectionStart = _box.TextLength;
            _box.ScrollToCaret();
        }
        catch (Exception ex) { Log("Log viewer append failed: " + ex.Message, LogLevel.Warning); }
    }

    public void RefreshState() => _enable.Checked = LoggerHost.IsEnabled;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            LoggerHost.OnLogLine -= OnLogLine;
            _drain.Stop();
            _drain.Dispose();
        }
        base.Dispose(disposing);
    }
}
