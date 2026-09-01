namespace VirusTotalScanner;

/// <summary>Reopens a history entry's full result from the cache — the shared flow behind the
/// overview's recent-scans strip and the history tab's double-click, so the "evicted from cache →
/// offer a rescan instead of a dead end" behaviour cannot drift apart between the two.</summary>
internal static class HistoryReopen
{
    public static void Show(HistoryEntry? e, IWin32Window? owner, Action<string[]>? rescan)
    {
        if (e == null) { UiFeedback.NeedSelection(); return; }
        var report = string.IsNullOrEmpty(e.Md5) ? null : AppServices.Cache.TryGet(e.Md5, int.MaxValue);
        if (report == null)
        {
            bool here = e.Path != null && File.Exists(e.Path);
            string head = string.Format(Strings.HistoryReopenHeadFormat, e.Name, e.Verdict, e.Ratio);
            if (here && NativeMessageBox.Confirm(head + Strings.HistoryReopenRescanSuffix)) rescan?.Invoke([e.Path!]);
            else if (!here) NativeMessageBox.Info(head + Strings.ReopenFileGoneSuffix + (e.Path ?? Strings.ReopenNoPath));
            return;
        }
        var item = new ScanItem(e.Path ?? e.Name) { Report = report, Status = ScanStatus.Completed, Md5 = e.Md5, Sha256 = e.Sha256 };
        using var dlg = new DetailDialog(item);
        dlg.ShowDialog(owner);
    }
}
