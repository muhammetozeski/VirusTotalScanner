namespace VirusTotalScanner;

/// <summary>
/// Turns VirusTotal's capability/behavior tags (and the crowd threat label) — both already present
/// in the file report — into a short plain-language "what this file does" line. No sandbox request:
/// it reads the tags VT attaches to the file object. Especially useful on 0-detection files.
/// </summary>
internal static class BehaviorTags
{
    // Ordered substring -> readable label. First match per tag wins; structural-only tags
    // (peexe, signed, 64bits, overlay…) are intentionally ignored — they are not behavior.
    // A property (not a cached field) so a runtime language switch is reflected in the labels.
    static (string Needle, string Label)[] Map =>
    [
        ("detect-debug", Strings.BtagDetectDebug),
        ("anti-debug", Strings.BtagAntiDebug),
        ("detect-vm", Strings.BtagDetectVm),
        ("checks-vm", Strings.BtagChecksVm),
        ("checks-network-adapters", Strings.BtagChecksNet),
        ("checks-cpu", Strings.BtagChecksCpu),
        ("checks-bios", Strings.BtagChecksBios),
        ("checks-disk", Strings.BtagChecksDisk),
        ("direct-cpu-clock-access", Strings.BtagCpuClock),
        ("long-sleeps", Strings.BtagLongSleeps),
        ("self-delete", Strings.BtagSelfDelete),
        ("persistence", Strings.BtagPersistence),
        ("autorun", Strings.BtagAutorun),
        ("runtime-modules", Strings.BtagRuntimeModules),
        ("create-process", Strings.BtagCreateProcess),
        ("spawn-process", Strings.BtagSpawnProcess),
        ("registry", Strings.BtagRegistry),
        ("keylogger", Strings.BtagKeylogger),
        ("contacts-", Strings.BtagContacts),
        ("communicates", Strings.BtagContacts),
        ("network", Strings.BtagNetwork),
        ("obfuscated", Strings.BtagObfuscated),
        ("packed", Strings.BtagPacked),
        ("exploit", Strings.BtagExploit),
        ("powershell", Strings.BtagPowershell),
        ("cve-", Strings.BtagCve),
    ];

    public static string? Summarize(IReadOnlyList<string> tags, string? threatLabel)
    {
        var labels = new List<string>();
        var seen = new HashSet<string>();
        foreach (var tag in tags)
        {
            if (string.IsNullOrWhiteSpace(tag)) continue;
            foreach (var (needle, label) in Map)
            {
                if (tag.Contains(needle, StringComparison.OrdinalIgnoreCase) && seen.Add(label))
                {
                    labels.Add(label);
                    break;
                }
            }
        }

        bool hasLabel = !string.IsNullOrWhiteSpace(threatLabel);
        if (labels.Count == 0 && !hasLabel) return null;

        string head = hasLabel ? string.Format(Strings.BtagClassFormat, threatLabel) : Strings.BtagBehavior;
        return labels.Count > 0 ? $"{head}  •  {string.Join("  •  ", labels.Take(8))}" : head;
    }
}
