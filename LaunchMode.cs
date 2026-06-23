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
    public bool Json;
    public bool Quiet;
    public bool Recurse;
    public bool NoTrust;
    public bool Keyless;
    public bool ShowHelp;
    public bool ShowVersion;
    public bool InstallMenu;
    public bool UninstallMenu;
    public bool RepairMenu;
    public bool ListKeys;
    public string? AddKeyValue;
    public string? RemoveKeyValue;
    public string? LookupHash;
    public string? SnapshotPath;
    public List<string> Paths { get; } = [];
}

internal static class ArgumentDef
{
    static readonly CmdArg Scan = new("--scan", "-s");
    static readonly CmdArg Recurse = new("--recurse", "-r");
    static readonly CmdArg NoTrust = new("--no-trust", "--notrust");
    static readonly CmdArg Keyless = new("--keyless", "-k");
    static readonly CmdArg NoGui = new("--nogui", "-n");
    static readonly CmdArg Cli = new("--cli", "-c");
    static readonly CmdArg Gui = new("--gui", "-g");
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
    static readonly CmdArg Snapshot = new("--snapshot", "--snapshot");

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
            else if (NoGui.IsMatch(a) || Cli.IsMatch(a)) o.NoGui = true;
            else if (Gui.IsMatch(a)) o.ForceGui = true;
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
            else if (Snapshot.IsMatch(a)) { if (i + 1 < args.Length) o.SnapshotPath = args[++i]; }
            else if (!a.StartsWith('-')) o.Paths.Add(a.Trim('"'));
        }
        return o;
    }
}
