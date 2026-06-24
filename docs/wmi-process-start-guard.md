# Real-time process-launch guard via WMI

## Problem
The app could only catch threats in watched folders (FileSystemWatcher) or via a manual "scan running
processes" snapshot. A fresh unknown exe double-clicked from chat/email that never touched a watched folder
got zero passive coverage until it was already running.

## Solution
Subscribe to the WMI `Win32_ProcessStartTrace` event and run each newly-launched image through the same
cheap-signal pipeline the download watcher uses (trust pre-filter → cache → keyless GUI), raising the same
`ThreatFound` event that already feeds auto-quarantine + toast.

```csharp
// needs the System.Management NuGet package (9.0.0 restores fine on net10.0-windows)
_watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
_watcher.EventArrived += OnProcessStarted;
_watcher.Start();

void OnProcessStarted(object s, EventArrivedEventArgs e) {
    int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
    string? path = null;
    try { using var p = Process.GetProcessById(pid); path = p.MainModule?.FileName; } catch { }
    if (!string.IsNullOrEmpty(path) && File.Exists(path)) _ = VerdictAsync(path);
}
```

## Gotchas
- **Needs admin.** The trace requires elevation. Off by default; degrade gracefully — if
  `!AdminHelper.IsRunningAsAdmin()`, log a warning and don't start. Never throw on a non-elevated machine.
- `Process.GetProcessById(pid).MainModule?.FileName` throws for short-lived / protected / access-denied
  processes — wrap it; a miss just means "nothing to check".
- Per-path `_inflight` dedupe so a burst of the same image isn't verdicted repeatedly.
- Can't be tested at the desk without admin — gate it behind a setting and rely on graceful degradation +
  a clean build; verify the WMI runtime in a dedicated elevated session.

## Takeaways
- WMI process-start tracing is the cleanest "catch it at launch" hook, but it's elevation-gated. Design the
  feature off-by-default with a graceful non-admin path so the build/ship is safe even where it can't run.
