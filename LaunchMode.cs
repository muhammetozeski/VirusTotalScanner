namespace VirusTotalScanner;

internal enum LaunchMode { Gui, GuiWithPaths, Cli }

/// <summary>A command-line flag with a long and short alias (TPMPass CmdArg pattern).</summary>
internal sealed class CmdArg(string longName, string shortName)
{
    public bool IsMatch(string input) =>
        !string.IsNullOrWhiteSpace(input) &&
        (input.Equals(longName, StringComparison.OrdinalIgnoreCase) ||
         input.Equals(shortName, StringComparison.OrdinalIgnoreCase));
}

internal sealed class CliOptions
{
    public bool ForceGui;
    public bool NoGui;
    public bool Tray;
    public bool Json;
    public bool Quiet;
    public bool Recurse;
    public bool NoTrust;
    public bool Keyless;
    public bool ExpandArchives;
    public bool Running;
    public bool VerifyBaseline;
    public string? DriftReport;
    public string? ExportLedger;
    public string? ImportLedger;
    public string? LedgerDiff;
    public int? TimelineDays;
    public bool WatchCheck;
    public bool ShowHelp;
    public bool ShowVersion;
    public bool InstallMenu;
    public bool UninstallMenu;
    public bool RepairMenu;
    public bool ListKeys;
    public string? AddKeyValue;
    public string? RemoveKeyValue;
    public string? LookupHash;
    public string? CommentsHash;
    public string? BehaviourHash;
    public string? ExpectedHash;
    public string? SnapshotPath;
    public string? ReportPath;
    public string? SweepResultPath; // machine-readable sweep outcome for the GUI to pick up
    public int FailOn = -1; // -1 = use verdict categories; >=0 = fail when any file hits >= N detections
    public string? DiffBaseline; // prior --report json to diff the current scan against
    public bool FailOnNew;
    public bool FailOnRegression;
    public List<string> Paths { get; } = [];
}

internal static class ArgumentDef
{
    static readonly CmdArg Scan = new("--scan", "-s");
    static readonly CmdArg Recurse = new("--recurse", "-r");
    static readonly CmdArg NoTrust = new("--no-trust", "--notrust");
    static readonly CmdArg Keyless = new("--keyless", "-k");
    static readonly CmdArg ExpandArchives = new("--expand-archives", "--expand");
    static readonly CmdArg Running = new("--running", "--processes");
    static readonly CmdArg VerifyBaseline = new("--verify-baseline", "--baseline");
    static readonly CmdArg DriftReport = new("--drift-report", "--drift");
    static readonly CmdArg ExportLedger = new("--export-ledger", "--export-ledger");
    static readonly CmdArg ImportLedger = new("--import-ledger", "--import-ledger");
    static readonly CmdArg LedgerDiff = new("--ledger-diff", "--ledger-diff");
    static readonly CmdArg Timeline = new("--timeline", "--timeline");
    static readonly CmdArg WatchCheck = new("--watch-check", "--watch-check");
    static readonly CmdArg NoGui = new("--nogui", "-n");
    static readonly CmdArg Cli = new("--cli", "-c");
    static readonly CmdArg Gui = new("--gui", "-g");
    static readonly CmdArg Tray = new("--tray", "--background");
    static readonly CmdArg Json = new("--json", "-j");
    static readonly CmdArg Quiet = new("--quiet", "-q");
    static readonly CmdArg Help = new("--help", "-h");
    static readonly CmdArg Version = new("--version", "-v");
    static readonly CmdArg Install = new("--install", "--install");
    static readonly CmdArg Uninstall = new("--uninstall", "--uninstall");
    static readonly CmdArg Repair = new("--repair", "--repair");
    static readonly CmdArg ListKeys = new("--listkeys", "--listkeys");
    static readonly CmdArg AddKey = new("--addkey", "--addkey");
    static readonly CmdArg RemoveKey = new("--removekey", "--removekey");
    static readonly CmdArg Lookup = new("--lookup", "--lookup");
    static readonly CmdArg Comments = new("--comments", "--comments");
    static readonly CmdArg Behaviour = new("--behaviour", "--behavior");
    static readonly CmdArg Expect = new("--expect", "--verify-hash");
    static readonly CmdArg Snapshot = new("--snapshot", "--snapshot");
    static readonly CmdArg Report = new("--report", "--report");
    static readonly CmdArg SweepResult = new("--sweep-result", "--sweep-result");
    static readonly CmdArg FailOn = new("--fail-on", "--failon");
    static readonly CmdArg Diff = new("--diff", "--diff");
    static readonly CmdArg FailOnNew = new("--fail-on-new", "--failonnew");
    static readonly CmdArg FailOnRegression = new("--fail-on-regression", "--failonreg");

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            if (Scan.IsMatch(a)) continue; // marker only
            else if (Recurse.IsMatch(a)) o.Recurse = true;
            else if (NoTrust.IsMatch(a)) o.NoTrust = true;
            else if (Keyless.IsMatch(a)) o.Keyless = true;
            else if (ExpandArchives.IsMatch(a)) o.ExpandArchives = true;
            else if (Running.IsMatch(a)) { o.Running = true; o.NoGui = true; }
            else if (VerifyBaseline.IsMatch(a)) { o.VerifyBaseline = true; o.NoGui = true; }
            else if (DriftReport.IsMatch(a)) { if (i + 1 < args.Length) o.DriftReport = args[++i]; o.NoGui = true; }
            else if (ExportLedger.IsMatch(a)) { if (i + 1 < args.Length) o.ExportLedger = args[++i]; o.NoGui = true; }
            else if (ImportLedger.IsMatch(a)) { if (i + 1 < args.Length) o.ImportLedger = args[++i]; o.NoGui = true; }
            else if (LedgerDiff.IsMatch(a)) { if (i + 1 < args.Length) o.LedgerDiff = args[++i]; o.NoGui = true; }
            else if (Timeline.IsMatch(a)) { o.TimelineDays = 60; if (i + 1 < args.Length && int.TryParse(args[i + 1], out var td)) { o.TimelineDays = td; i++; } o.NoGui = true; }
            else if (WatchCheck.IsMatch(a)) { o.WatchCheck = true; o.NoGui = true; }
            else if (NoGui.IsMatch(a) || Cli.IsMatch(a)) o.NoGui = true;
            else if (Gui.IsMatch(a)) o.ForceGui = true;
            else if (Tray.IsMatch(a)) { o.Tray = true; o.ForceGui = true; }
            else if (Json.IsMatch(a)) { o.Json = true; o.NoGui = true; }
            else if (Quiet.IsMatch(a)) o.Quiet = true;
            else if (Help.IsMatch(a) || a == "-?" || a == "/?") o.ShowHelp = true;
            else if (Version.IsMatch(a)) o.ShowVersion = true;
            else if (Install.IsMatch(a)) o.InstallMenu = true;
            else if (Uninstall.IsMatch(a)) o.UninstallMenu = true;
            else if (Repair.IsMatch(a)) o.RepairMenu = true;
            else if (ListKeys.IsMatch(a)) { o.ListKeys = true; o.NoGui = true; }
            else if (AddKey.IsMatch(a)) { if (i + 1 < args.Length) o.AddKeyValue = args[++i]; o.NoGui = true; }
            else if (RemoveKey.IsMatch(a)) { if (i + 1 < args.Length) o.RemoveKeyValue = args[++i]; o.NoGui = true; }
            else if (Lookup.IsMatch(a)) { if (i + 1 < args.Length) o.LookupHash = args[++i]; o.NoGui = true; }
            else if (Comments.IsMatch(a)) { if (i + 1 < args.Length) o.CommentsHash = args[++i]; o.NoGui = true; o.Keyless = true; }
            else if (Behaviour.IsMatch(a)) { if (i + 1 < args.Length) o.BehaviourHash = args[++i]; o.NoGui = true; o.Keyless = true; }
            else if (Expect.IsMatch(a)) { if (i + 1 < args.Length) o.ExpectedHash = args[++i]; o.NoGui = true; }
            else if (Snapshot.IsMatch(a)) { if (i + 1 < args.Length) o.SnapshotPath = args[++i]; }
            else if (Report.IsMatch(a)) { if (i + 1 < args.Length) o.ReportPath = args[++i]; o.NoGui = true; }
            else if (SweepResult.IsMatch(a)) { if (i + 1 < args.Length) o.SweepResultPath = args[++i]; o.NoGui = true; }
            else if (FailOn.IsMatch(a)) { if (i + 1 < args.Length && int.TryParse(args[++i], out var n)) o.FailOn = n; o.NoGui = true; }
            else if (Diff.IsMatch(a)) { if (i + 1 < args.Length) o.DiffBaseline = args[++i]; o.NoGui = true; }
            else if (FailOnNew.IsMatch(a)) { o.FailOnNew = true; o.NoGui = true; }
            else if (FailOnRegression.IsMatch(a)) { o.FailOnRegression = true; o.NoGui = true; }
            else if (!a.StartsWith('-')) o.Paths.Add(a.Trim('"'));
        }
        return o;
    }
}
