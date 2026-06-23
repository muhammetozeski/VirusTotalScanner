using System.Drawing;

namespace VirusTotalScanner;

/// <summary>"Loglar" tab: live log stream + on/off toggle, clear, copy-all, open folder.</summary>
internal sealed class LogViewerControl : UserControl
{
    readonly RichTextBox _box = new();
    readonly CheckBox _enable = new();
    int _lines;
    const int MaxLines = 3000;

    public LogViewerControl()
    {
        Dock = DockStyle.Fill;
        Padding = new Padding(8);

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true };
        _enable.Text = "Loglama açık";
        _enable.AutoSize = true;
        _enable.Checked = LoggerHost.IsEnabled;
        _enable.Margin = new Padding(6, 8, 12, 4);
        _enable.CheckedChanged += (_, _) => LoggerHost.SetEnabled(_enable.Checked);
        bar.Controls.Add(_enable);
        bar.Controls.Add(ThemeManager.MakeButton("Temizle", (_, _) => { _box.Clear(); _lines = 0; Logger.ClearAllLogs(); }));
        bar.Controls.Add(ThemeManager.MakeButton("Tümünü kopyala", (_, _) => { try { Clipboard.SetText(Logger.GetAllLogsText()); } catch { } }));
        bar.Controls.Add(ThemeManager.MakeButton("Log klasörünü aç", (_, _) =>
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

        LoggerHost.OnLogLine += OnLogLine;
    }

    void OnLogLine(string line)
    {
        if (!IsHandleCreated) return;
        try
        {
            BeginInvoke(() =>
            {
                if (_lines >= MaxLines)
                {
                    _box.Clear();
                    _lines = 0;
                }
                _box.AppendText(line.TrimEnd() + Environment.NewLine);
                _lines++;
                _box.SelectionStart = _box.TextLength;
                _box.ScrollToCaret();
            });
        }
        catch { }
    }

    public void RefreshState() => _enable.Checked = LoggerHost.IsEnabled;
}
