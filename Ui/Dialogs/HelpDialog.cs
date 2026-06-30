using System.Drawing;

namespace VirusTotalScanner;

/// <summary>A browsable, plain-Turkish glossary of the dense signals the app shows, so the meaning of
/// "konsensüs", "nadirlik", "imza vs sezgisel" etc. is one click away — not just discoverable on hover.</summary>
internal sealed class HelpDialog : Form
{
    static readonly (string Term, string Meaning)[] Glossary =
    [
        (Strings.HelpTermShortcuts, Strings.HelpMeaningShortcuts),
        (Strings.HelpTermVerdict, Strings.HelpMeaningVerdict),
        (Strings.HelpTermConsensus, Strings.HelpMeaningConsensus),
        (Strings.HelpTermSignatureHeuristic, Strings.HelpMeaningSignatureHeuristic),
        (Strings.HelpTermFirstSeen, Strings.HelpMeaningFirstSeen),
        (Strings.HelpTermFamily, Strings.HelpMeaningFamily),
        (Strings.HelpTermSignatureTrust, Strings.HelpMeaningSignatureTrust),
        (Strings.HelpTermDownloadSource, Strings.HelpMeaningDownloadSource),
        (Strings.HelpTermBehaviour, Strings.HelpMeaningBehaviour),
        (Strings.HelpTermOverlay, Strings.HelpMeaningOverlay),
        (Strings.HelpTermStale, Strings.HelpMeaningStale),
        (Strings.HelpTermQuarantine, Strings.HelpMeaningQuarantine),
        (Strings.HelpTermKeyless, Strings.HelpMeaningKeyless),
    ];

    public HelpDialog(string? jumpTo = null)
    {
        Text = Strings.HelpDlgTitle;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(680, 560);
        MinimumSize = new Size(480, 360);

        var box = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            DetectUrls = false,
            Font = new Font("Segoe UI", 10f),
            Margin = new Padding(0),
        };

        var close = new Button { Text = Strings.BtnClose, DialogResult = DialogResult.OK, Dock = DockStyle.Right, Width = 100 };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 46, Padding = new Padding(10, 7, 10, 7) };
        bottom.Controls.Add(close);
        var pad = new Panel { Dock = DockStyle.Fill, Padding = new Padding(14, 12, 14, 4) };
        pad.Controls.Add(box);

        Controls.Add(pad);
        Controls.Add(bottom);
        CancelButton = close;

        ThemeManager.Apply(this);
        ThemeManager.StyleButton(close);

        var t = Theme.Current;
        box.BackColor = t.Panel;
        box.ForeColor = t.Text;
        int jumpOffset = -1;
        foreach (var (term, meaning) in Glossary)
        {
            if (jumpOffset < 0 && !string.IsNullOrEmpty(jumpTo) && term.Contains(jumpTo, StringComparison.OrdinalIgnoreCase))
                jumpOffset = box.TextLength; // start of the matched term
            box.SelectionFont = new Font("Segoe UI", 10.5f, FontStyle.Bold);
            box.SelectionColor = t.Accent;
            box.AppendText(term + "\n");
            box.SelectionFont = new Font("Segoe UI", 10f, FontStyle.Regular);
            box.SelectionColor = t.Text;
            box.AppendText(meaning + "\n\n");
        }
        box.SelectionStart = jumpOffset >= 0 ? jumpOffset : 0;
        box.ScrollToCaret();
    }
}
