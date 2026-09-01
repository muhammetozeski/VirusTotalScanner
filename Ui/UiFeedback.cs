namespace VirusTotalScanner;

/// <summary>
/// The one place a user action says "I did nothing, and here is why". A dozen handlers used to answer a
/// click with a bare <c>return</c> when nothing was selected or the file was gone, so the button looked
/// broken. Every refusal is both shown to the user and pushed into <see cref="UiStatusHub"/>, so the
/// status bar keeps the trace after the message box is dismissed.
/// </summary>
internal static class UiFeedback
{
    /// <summary>The action needs a selected row and none is usable. <paramref name="action"/> is the
    /// action's own visible label when the call site has one, and titles the message box.</summary>
    public static void NeedSelection(string? action = null) => Refused(Strings.NeedSelectionInfo, action);

    /// <summary>The action was refused for a reason of its own (file gone, row not scanned yet…).</summary>
    public static void Refused(string reason, string? action = null)
    {
        UiStatusHub.Report(action ?? Strings.FeedbackSource, reason, StatusSeverity.Warning);
        NativeMessageBox.Info(reason, action);
    }
}
