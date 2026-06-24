using System.Diagnostics;

namespace VirusTotalScanner;

/// <summary>
/// Reads a PE file's self-declared identity (version-resource strings) and contradicts it against
/// reality (the Authenticode signer the app already computes). A file resourced as "Microsoft
/// Corporation" but unsigned, or carrying an embedded OriginalFilename different from its on-disk
/// name, is a strong, cheap malware tell — and entirely invisible to a hash/verdict lookup. Local,
/// BCL-only, zero quota.
/// </summary>
internal static class PeIdentityService
{
    static readonly string[] KnownVendors =
    [
        "microsoft", "google", "adobe", "mozilla", "oracle", "apple", "intel", "nvidia",
        "valve", "amazon", "cisco", "vmware", "dropbox", "spotify", "discord", "realtek",
    ];

    static readonly HashSet<string> PeExts = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl" };

    /// <summary>One identity line for the detail pane, or null when nothing notable / not a PE.</summary>
    public static string? IdentitySummary(string path, TrustResult trust)
    {
        try
        {
            if (string.IsNullOrEmpty(path) || !PeExts.Contains(Path.GetExtension(path)) || !File.Exists(path)) return null;

            var fvi = FileVersionInfo.GetVersionInfo(path);
            string? company = fvi.CompanyName?.Trim();
            string? orig = fvi.OriginalFilename?.Trim();
            string onDisk = Path.GetFileName(path);
            var notes = new List<string>();

            // Impersonation: resource claims a known vendor but the file isn't signed by them.
            if (!string.IsNullOrEmpty(company))
            {
                string cl = company.ToLowerInvariant();
                string? claimed = KnownVendors.FirstOrDefault(v => cl.Contains(v));
                if (claimed != null)
                {
                    bool signedBySame = trust.Trusted && trust.Publisher != null &&
                        trust.Publisher.Contains(claimed, StringComparison.OrdinalIgnoreCase);
                    if (!signedBySame)
                        notes.Add($"⚠ '{company}' olduğunu iddia ediyor ama imza {(trust.Trusted ? "farklı: " + trust.Publisher : "yok/geçersiz")} — TAKLİT olabilir");
                }
            }

            // Filename masquerade: the embedded OriginalFilename differs from the on-disk name.
            if (!string.IsNullOrEmpty(orig) &&
                orig.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(orig, onDisk, StringComparison.OrdinalIgnoreCase))
                notes.Add($"📛 gömülü ad '{orig}' ≠ disk adı '{onDisk}'");

            if (notes.Count > 0) return "🪪 " + string.Join("  •  ", notes);

            // Otherwise a benign one-line identity, if there is one.
            string? id = !string.IsNullOrEmpty(company) ? company
                : !string.IsNullOrEmpty(fvi.ProductName) ? fvi.ProductName!.Trim()
                : null;
            return string.IsNullOrEmpty(id) ? null : $"🪪 Kimlik: {id}";
        }
        catch (Exception ex) { Log("PE identity read failed: " + ex.Message, LogLevel.Warning); return null; }
    }
}
