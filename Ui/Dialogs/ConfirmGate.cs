using System.Drawing;
using System.Reflection;
using System.Text.Json;

namespace VirusTotalScanner;

/// <summary>A confirmable action that supports a remembered "don't ask again" choice.</summary>
internal sealed class ConfirmGate(string title, string question)
{
    public string Key { get; internal set; } = "";
    public string Title { get; } = title;
    public string Question { get; } = question;
    public bool Suppressed { get; set; }
    public bool RememberedAnswer { get; set; }

    /// <summary>Asks (unless suppressed). Returns the answer; persists "don't ask again" if chosen.</summary>
    public bool Ask(IWin32Window? owner, string? questionOverride = null)
    {
        if (Suppressed) return RememberedAnswer;
        var (answer, dontAsk) = ConfirmDialog.Show(owner, Title, questionOverride ?? Question);
        if (dontAsk) { Suppressed = true; RememberedAnswer = answer; ConfirmGateManager.Save(); }
        return answer;
    }

    public void ResetSuppression() { Suppressed = false; ConfirmGateManager.Save(); }
}

/// <summary>All confirmable actions. Each public static field is auto-registered by reflection.</summary>
internal static class ConfirmGates
{
    public static readonly ConfirmGate Quarantine =
        new(Strings.GateQuarantineTitle, Strings.GateQuarantineQuestion);

    public static readonly ConfirmGate ContextMenuInstall =
        new(Strings.GateContextMenuInstallTitle, Strings.GateContextMenuInstallQuestion);

    public static readonly ConfirmGate ClearCache =
        new(Strings.CmdClearCacheName, Strings.GateClearCacheQuestion);

    public static readonly ConfirmGate DeleteKey =
        new(Strings.GateDeleteKeyTitle, Strings.GateDeleteKeyQuestion);
}

/// <summary>
/// Reflection-registers every <see cref="ConfirmGate"/> in <see cref="ConfirmGates"/>, persists
/// their "don't ask again" state (confirm-gates.json next to the exe), and exposes them so the
/// settings UI can list and re-enable any that were suppressed.
/// </summary>
internal static class ConfirmGateManager
{
    static readonly Dictionary<string, ConfirmGate> _gates = [];
    static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    static ConfirmGateManager()
    {
        foreach (var f in typeof(ConfirmGates).GetFields(BindingFlags.Public | BindingFlags.Static))
            if (f.GetValue(null) is ConfirmGate g) { g.Key = f.Name; _gates[f.Name] = g; }
    }

    public static IEnumerable<ConfirmGate> All => _gates.Values;
    static string FilePath => Path.Combine(ConfigPathResolver.ConfigFolder, "confirm-gates.json");

    sealed class GateState { public bool Suppressed { get; set; } public bool Answer { get; set; } }

    public static void Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return;
            var map = JsonSerializer.Deserialize<Dictionary<string, GateState>>(File.ReadAllText(FilePath), JsonOpts);
            if (map == null) return;
            foreach (var (key, st) in map)
                if (_gates.TryGetValue(key, out var g)) { g.Suppressed = st.Suppressed; g.RememberedAnswer = st.Answer; }
        }
        catch (Exception ex) { Log("Confirm gates load failed: " + ex.Message, LogLevel.Warning); }
    }

    public static void Save()
    {
        try
        {
            var map = _gates.ToDictionary(kv => kv.Key, kv => new GateState { Suppressed = kv.Value.Suppressed, Answer = kv.Value.RememberedAnswer });
            Directory.CreateDirectory(ConfigPathResolver.ConfigFolder);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(map, JsonOpts));
        }
        catch (Exception ex) { Log("Confirm gates save failed: " + ex.Message, LogLevel.Warning); }
    }
}

/// <summary>Yes/No dialog with a "Bir daha sorma" (don't ask again) checkbox.</summary>
internal static class ConfirmDialog
{
    public static (bool answer, bool dontAskAgain) Show(IWin32Window? owner, string title, string question)
    {
        using var form = new Form
        {
            Text = title,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false,
            MaximizeBox = false,
            ClientSize = new Size(460, 160),
        };
        var lbl = new Label { Text = question, Left = 14, Top = 14, Width = 432, Height = 64, AutoSize = false };
        var dontAsk = new CheckBox { Text = Strings.ConfirmDontAskAgain, Left = 14, Top = 86, AutoSize = true };
        var yes = new Button { Text = Strings.GateYes, DialogResult = DialogResult.Yes, Left = 270, Top = 116, Width = 80 };
        var no = new Button { Text = Strings.GateNo, DialogResult = DialogResult.No, Left = 360, Top = 116, Width = 80 };
        form.Controls.AddRange([lbl, dontAsk, yes, no]);
        form.AcceptButton = yes;
        form.CancelButton = no;
        ThemeManager.Apply(form);
        ThemeManager.StyleButton(yes, accent: true);
        ThemeManager.StyleButton(no);

        var r = owner != null ? form.ShowDialog(owner) : form.ShowDialog();
        return (r == DialogResult.Yes, dontAsk.Checked);
    }
}
