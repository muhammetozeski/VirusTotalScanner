namespace VirusTotalScanner;

/// <summary>Thin MessageBox wrapper for GUI prompts (permission, confirmations, info).</summary>
internal static class NativeMessageBox
{
    public static bool Confirm(string text, string? caption = null) =>
        MessageBox.Show(text, caption ?? AppConstants.AppTitle,
            MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button1) == DialogResult.Yes;

    public static void Info(string text, string? caption = null) =>
        MessageBox.Show(text, caption ?? AppConstants.AppTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);

    public static void Warn(string text, string? caption = null) =>
        MessageBox.Show(text, caption ?? AppConstants.AppTitle, MessageBoxButtons.OK, MessageBoxIcon.Warning);

    public static void Error(string text, string? caption = null) =>
        MessageBox.Show(text, caption ?? AppConstants.AppTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
}
