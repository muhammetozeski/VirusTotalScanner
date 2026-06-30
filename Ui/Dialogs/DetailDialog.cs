using System.Drawing;

namespace VirusTotalScanner;

/// <summary>A standalone window hosting a <see cref="ScanDetailControl"/>, used to reopen a past
/// result (e.g. from the history tab) without disturbing the live scan queue.</summary>
internal sealed class DetailDialog : Form
{
    public DetailDialog(ScanItem item)
    {
        Text = item.FileName;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(640, 560);
        MinimumSize = new Size(480, 400);

        var detail = new ScanDetailControl { Dock = DockStyle.Fill };
        Controls.Add(detail);

        ThemeManager.Apply(this);
        detail.ApplyTheme();
        detail.Show(item);
    }
}
