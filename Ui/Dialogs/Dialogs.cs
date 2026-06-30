using System.Drawing;

namespace VirusTotalScanner;

/// <summary>Small reusable dialogs (WinForms has no built-in InputBox).</summary>
internal static class Dialogs
{
    public static string? InputBox(string prompt, string title, string defaultValue = "")
    {
        using var form = new Form
        {
            Text = title,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = false,
            ClientSize = new Size(460, 130),
        };
        var label = new Label { Text = prompt, Left = 12, Top = 12, Width = 436, AutoSize = false, Height = 36 };
        var tb = new TextBox { Left = 12, Top = 52, Width = 436, Text = defaultValue };
        var ok = new Button { Text = Strings.BtnOk, DialogResult = DialogResult.OK, Left = 292, Top = 88, Width = 75 };
        var cancel = new Button { Text = Strings.DlgCancel, DialogResult = DialogResult.Cancel, Left = 373, Top = 88, Width = 75 };
        form.Controls.AddRange([label, tb, ok, cancel]);
        form.AcceptButton = ok;
        form.CancelButton = cancel;

        ThemeManager.Apply(form);
        return form.ShowDialog() == DialogResult.OK ? tb.Text.Trim() : null;
    }
}
