namespace VirusTotalScanner;

/// <summary>
/// Pool of 350+ realistic modern desktop browser User-Agent strings. Every HTTP request and every
/// WebView2 navigation picks a random entry so the application name is never sent to VirusTotal.
/// </summary>
internal static class UserAgentPool
{
    static readonly string[] WindowsChromiumAgents = BuildWindowsChromiumAgents();
    static readonly string[] AllBrowserAgents = BuildAllBrowserAgents(WindowsChromiumAgents);

    /// <summary>Total count of distinct browser User-Agents in the general HTTP pool.</summary>
    public static int TotalCount => AllBrowserAgents.Length;

    /// <summary>Total count of Windows Chromium User-Agents in the WebView2 pool.</summary>
    public static int ChromiumWindowsCount => WindowsChromiumAgents.Length;

    /// <summary>Picks a uniformly random realistic desktop browser User-Agent (Chrome, Edge, Firefox, Safari).</summary>
    public static string Pick() => AllBrowserAgents[Random.Shared.Next(AllBrowserAgents.Length)];

    /// <summary>Picks a uniformly random Windows Chromium (Chrome / Edge) User-Agent matching WebView2's engine.</summary>
    public static string PickChromiumWindows() => WindowsChromiumAgents[Random.Shared.Next(WindowsChromiumAgents.Length)];

    static string[] BuildWindowsChromiumAgents()
    {
        var list = new List<string>(240);

        // Real Chrome Desktop release families (major.0.build.patch) on Windows 10/11 x64
        (int Major, int Build, int[] Patches)[] chromeReleases =
        [
            (122, 6261, [57, 69, 94, 111, 128]),
            (123, 6312, [58, 86, 105, 122]),
            (124, 6367, [60, 78, 91, 118, 155, 201, 207]),
            (125, 6422, [60, 76, 112, 141, 142, 175]),
            (126, 6478, [56, 61, 114, 126, 182, 185]),
            (127, 6533, [72, 88, 99, 119, 120]),
            (128, 6613, [84, 113, 119, 137, 138]),
            (129, 6668, [58, 70, 89, 100, 101]),
            (130, 6723, [58, 69, 91, 116, 117]),
            (131, 6778, [69, 85, 108, 139, 204, 264]),
            (132, 6834, [83, 110, 159, 160, 196]),
            (133, 6943, [53, 98, 126, 141, 142]),
            (134, 6998, [35, 88, 117, 165, 166]),
            (135, 7049, [41, 84, 95, 114, 115]),
            (136, 7103, [48, 92, 93, 113, 114]),
            (137, 7151, [40, 55, 68, 103, 119]),
            (138, 7204, [49, 96, 100, 157, 168]),
            (139, 7258, [66, 127, 138, 154]),
            (140, 7339, [80, 127, 185, 207]),
            (141, 7390, [54, 65, 107, 122]),
            (142, 7444, [59, 60, 134, 175]),
        ];

        foreach (var (major, build, patches) in chromeReleases)
        {
            // Both Chromium reduced UA (major.0.0.0) and full build variants
            list.Add($"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36");
            foreach (int patch in patches)
                list.Add($"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.{build}.{patch} Safari/537.36");
        }

        // Real Microsoft Edge (Chromium) release families on Windows 10/11 x64
        (int Major, int EdgeBuild, int[] EdgePatches)[] edgeReleases =
        [
            (122, 2365, [52, 59, 66, 80, 92]),
            (123, 2420, [53, 65, 81, 97]),
            (124, 2478, [51, 67, 80, 97]),
            (125, 2535, [51, 67, 79, 85, 92]),
            (126, 2592, [56, 68, 81, 102, 113]),
            (127, 2651, [74, 86, 98, 105]),
            (128, 2739, [42, 54, 67, 79]),
            (129, 2792, [52, 65, 79, 84]),
            (130, 2849, [46, 56, 68, 80]),
            (131, 2903, [51, 63, 70, 86, 112]),
            (132, 2957, [115, 127, 140, 158]),
            (133, 3065, [51, 69, 82, 92]),
            (134, 3124, [51, 66, 72, 83, 93]),
            (135, 3179, [54, 66, 73, 85]),
            (136, 3240, [50, 64, 76, 92]),
            (137, 3296, [52, 68, 83, 93]),
            (138, 3351, [55, 65, 83, 98]),
            (139, 3405, [86, 102, 119, 125]),
            (140, 3485, [54, 66, 81, 94]),
            (141, 3537, [57, 71, 85, 99]),
            (142, 3595, [53, 65, 80, 94]),
        ];

        foreach (var (major, build, patches) in edgeReleases)
        {
            list.Add($"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36 Edg/{major}.0.0.0");
            foreach (int patch in patches)
                list.Add($"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36 Edg/{major}.0.{build}.{patch}");
        }

        // Real Opera (Chromium) releases on Windows x64
        (int ChromeMajor, int OperaMajor, int[] Builds)[] operaReleases =
        [
            (124, 110, [5130, 5130]),
            (126, 112, [5197]),
            (128, 114, [5282]),
            (130, 115, [5322]),
            (132, 117, [5408]),
            (134, 118, [5461]),
            (136, 119, [5497]),
            (138, 120, [5543]),
            (140, 122, [5643]),
        ];
        foreach (var (cm, om, builds) in operaReleases)
            foreach (int b in builds.Distinct())
                list.Add($"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{cm}.0.0.0 Safari/537.36 OPR/{om}.0.{b}.0");

        return list.Distinct(StringComparer.Ordinal).ToArray();
    }

    static string[] BuildAllBrowserAgents(string[] windowsChromium)
    {
        var list = new List<string>(windowsChromium.Length + 180);
        list.AddRange(windowsChromium);

        // macOS Chrome & Edge across macOS 13–15
        string[] macOsVersions = ["10_15_7", "13_6_9", "14_5", "14_7_1", "15_0", "15_2", "15_4"];
        int[] macChromeMajors = [124, 126, 128, 130, 131, 132, 133, 134, 135, 136, 138, 140, 142];
        foreach (string mac in macOsVersions)
            foreach (int m in macChromeMajors)
                list.Add($"Mozilla/5.0 (Macintosh; Intel Mac OS X {mac}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{m}.0.0.0 Safari/537.36");

        // macOS Safari
        (string Mac, string Safari)[] safariReleases =
        [
            ("10_15_7", "17.4.1"), ("10_15_7", "17.5"), ("10_15_7", "17.6"),
            ("10_15_7", "18.0"), ("10_15_7", "18.1"), ("10_15_7", "18.2"), ("10_15_7", "18.3"), ("10_15_7", "18.4"),
            ("14_5", "17.5"), ("14_7_1", "18.0.1"), ("15_0", "18.0"), ("15_2", "18.2"), ("15_4", "18.4"),
        ];
        foreach (var (mac, sf) in safariReleases)
            list.Add($"Mozilla/5.0 (Macintosh; Intel Mac OS X {mac}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{sf} Safari/605.1.15");

        // Linux Chrome & Firefox
        string[] linuxPlatforms = ["X11; Linux x86_64", "X11; Ubuntu; Linux x86_64", "X11; Fedora; Linux x86_64"];
        int[] linuxChromeMajors = [125, 127, 129, 131, 133, 135, 137, 139, 141];
        foreach (string lp in linuxPlatforms)
            foreach (int m in linuxChromeMajors)
                list.Add($"Mozilla/5.0 ({lp}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{m}.0.0.0 Safari/537.36");

        // Firefox on Windows, macOS, Linux
        int[] firefoxVersions = [124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 142];
        foreach (int ff in firefoxVersions)
        {
            list.Add($"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{ff}.0) Gecko/20100101 Firefox/{ff}.0");
            list.Add($"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:{ff}.0) Gecko/20100101 Firefox/{ff}.0");
            list.Add($"Mozilla/5.0 (X11; Linux x86_64; rv:{ff}.0) Gecko/20100101 Firefox/{ff}.0");
        }

        return list.Distinct(StringComparer.Ordinal).ToArray();
    }
}
