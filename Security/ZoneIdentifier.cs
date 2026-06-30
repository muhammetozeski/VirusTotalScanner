namespace VirusTotalScanner;

/// <summary>Where a file came from, read from the NTFS <c>:Zone.Identifier</c> alternate data
/// stream that Windows writes on download. A "this exe was downloaded from the internet" mark is
/// a useful provenance signal next to the VT verdict.</summary>
internal sealed class ZoneInfo
{
    public int ZoneId { get; init; } = -1;
    public string? ReferrerUrl { get; init; }
    public string? HostUrl { get; init; }

    public bool FromInternet => ZoneId is 3 or 4;

    public string ZoneName => ZoneId switch
    {
        0 => Strings.ZoneLocalMachine,
        1 => Strings.ZoneLocalNetwork,
        2 => Strings.ZoneTrustedSite,
        3 => Strings.ZoneInternet,
        4 => Strings.ZoneRestrictedSite,
        _ => Strings.StatusUnknown,
    };

    /// <summary>Provenance summary for the detail pane, or null if there is no zone mark. When the download
    /// CDN/host and the referring page are both known and differ, both are shown on their own lines — the
    /// real origin evidence is the page the user clicked, not the CDN it was served from.</summary>
    public string? Summary
    {
        get
        {
            string warn = FromInternet ? Strings.ZoneDownloadedWarn : "";
            bool bothDiffer = !string.IsNullOrEmpty(HostUrl) && !string.IsNullOrEmpty(ReferrerUrl)
                && !string.Equals(HostUrl, ReferrerUrl, StringComparison.OrdinalIgnoreCase);
            if (bothDiffer)
                return string.Format(Strings.ZoneSummaryBothFormat, ZoneName, warn, HostUrl, ReferrerUrl);

            string src = HostUrl ?? ReferrerUrl ?? "";
            string where = src.Length > 0 ? string.Format(Strings.ZoneSourceSuffixFormat, src) : "";
            return string.Format(Strings.ZoneSummaryFormat, ZoneName, where, warn);
        }
    }
}

internal static class ZoneIdentifier
{
    /// <summary>Reads the Zone.Identifier ADS for a file, or null if absent / not on NTFS.</summary>
    public static ZoneInfo? Read(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return null;
        if (!File.Exists(filePath)) return null;
        string content;
        try
        {
            // The zone mark lives in a named NTFS stream; reading it throws FileNotFound when the
            // file has no such stream (the common case) or when the volume is not NTFS.
            content = File.ReadAllText(filePath + ":Zone.Identifier");
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
        catch (IOException) { return null; }
        catch (Exception ex) { Log("Zone.Identifier read failed: " + ex.Message, LogLevel.Warning); return null; }

        try
        {

            int zone = -1;
            string? referrer = null, host = null;
            foreach (var raw in content.Split('\n'))
            {
                var line = raw.Trim();
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                string key = line[..eq].Trim();
                string val = line[(eq + 1)..].Trim();
                if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase)) int.TryParse(val, out zone);
                else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase)) referrer = val;
                else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase)) host = val;
            }
            if (zone < 0 && referrer == null && host == null) return null;
            return new ZoneInfo { ZoneId = zone, ReferrerUrl = referrer, HostUrl = host };
        }
        catch (Exception ex)
        {
            Log("Zone.Identifier read failed: " + ex.Message, LogLevel.Warning);
            return null;
        }
    }
}
