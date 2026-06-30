using System.Text.RegularExpressions;

namespace VirusTotalScanner;

/// <summary>Offline decoder for MITRE ATT&CK technique ids → plain-Turkish "what it means", grouped by
/// tactic. Turns the jargon ids in a sandbox report into statements a non-expert can read. Mirrors the
/// shipped <see cref="JargonGlossary"/> pattern: pure local lookup, no quota.</summary>
internal static class MitreGlossary
{
    // technique id (base, no sub-technique suffix) → (tactic heading, one-sentence meaning)
    static readonly Dictionary<string, (string Tactic, string Meaning)> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["T1547"] = (Strings.MitreTacticPersistence, Strings.MitreMeaningT1547),
        ["T1053"] = (Strings.MitreTacticPersistence, Strings.MitreMeaningT1053),
        ["T1543"] = (Strings.MitreTacticPersistence, Strings.MitreMeaningT1543),
        ["T1546"] = (Strings.MitreTacticPersistence, Strings.MitreMeaningT1546),
        ["T1055"] = (Strings.MitreTacticDefenseEvasion, Strings.MitreMeaningT1055),
        ["T1027"] = (Strings.MitreTacticDefenseEvasion, Strings.MitreMeaningT1027),
        ["T1112"] = (Strings.MitreTacticDefenseEvasion, Strings.MitreMeaningT1112),
        ["T1070"] = (Strings.MitreTacticDefenseEvasion, Strings.MitreMeaningT1070),
        ["T1562"] = (Strings.MitreTacticDefenseEvasion, Strings.MitreMeaningT1562),
        ["T1497"] = (Strings.MitreTacticDefenseEvasion, Strings.MitreMeaningT1497),
        ["T1486"] = (Strings.MitreTacticImpact, Strings.MitreMeaningT1486),
        ["T1490"] = (Strings.MitreTacticImpact, Strings.MitreMeaningT1490),
        ["T1489"] = (Strings.MitreTacticImpact, Strings.MitreMeaningT1489),
        ["T1071"] = (Strings.MitreTacticCommandControl, Strings.MitreMeaningT1071),
        ["T1105"] = (Strings.MitreTacticCommandControl, Strings.MitreMeaningT1105),
        ["T1095"] = (Strings.MitreTacticCommandControl, Strings.MitreMeaningT1095),
        ["T1041"] = (Strings.MitreTacticExfiltration, Strings.MitreMeaningT1041),
        ["T1056"] = (Strings.MitreTacticCredentialTheft, Strings.MitreMeaningT1056),
        ["T1003"] = (Strings.MitreTacticCredentialTheft, Strings.MitreMeaningT1003),
        ["T1059"] = (Strings.MitreTacticExecution, Strings.MitreMeaningT1059),
        ["T1204"] = (Strings.MitreTacticExecution, Strings.MitreMeaningT1204),
        ["T1082"] = (Strings.MitreTacticDiscovery, Strings.MitreMeaningT1082),
        ["T1083"] = (Strings.MitreTacticDiscovery, Strings.MitreMeaningT1083),
        ["T1057"] = (Strings.MitreTacticDiscovery, Strings.MitreMeaningT1057),
        ["T1518"] = (Strings.MitreTacticDiscovery, Strings.MitreMeaningT1518),
        ["T1016"] = (Strings.MitreTacticDiscovery, Strings.MitreMeaningT1016),
        ["T1021"] = (Strings.MitreTacticLateralMovement, Strings.MitreMeaningT1021),
        ["T1036"] = (Strings.MitreTacticDefenseEvasion, Strings.MitreMeaningT1036),
    };

    static readonly Regex IdRx = new(@"T\d{4}", RegexOptions.Compiled);

    static string BaseId(string raw) { var m = IdRx.Match(raw); return m.Success ? m.Value : raw; }

    static string Description(string raw)
    {
        int sp = raw.IndexOf(' ');
        return sp >= 0 ? raw[(sp + 1)..].Trim() : raw;
    }

    /// <summary>Decode raw "{id} {description}" entries into tactic → distinct meanings, preserving the
    /// order tactics first appear. Unknown ids fall under "Diğer teknikler" with their raw description.</summary>
    public static List<(string Tactic, List<string> Meanings)> Decode(IEnumerable<string> raw)
    {
        var groups = new Dictionary<string, List<string>>();
        var order = new List<string>();
        foreach (var entry in raw)
        {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            string tactic, meaning;
            if (Map.TryGetValue(BaseId(entry), out var hit)) { tactic = hit.Tactic; meaning = hit.Meaning; }
            else { tactic = Strings.MitreTacticOther; meaning = Description(entry); }
            if (!groups.TryGetValue(tactic, out var list)) { list = []; groups[tactic] = list; order.Add(tactic); }
            if (!list.Contains(meaning)) list.Add(meaning);
        }
        return order.Select(t => (t, groups[t])).ToList();
    }

    /// <summary>The tactics that mean real damage — coloured as an alarm in the digest.</summary>
    public static bool IsAlarmTactic(string tactic) =>
        tactic == Strings.MitreTacticImpact || tactic == Strings.MitreTacticPersistence || tactic == Strings.MitreTacticCredentialTheft;
}
