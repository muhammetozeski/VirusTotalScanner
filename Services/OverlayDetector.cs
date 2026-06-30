using System.Reflection.PortableExecutable;

namespace VirusTotalScanner;

/// <summary>
/// Detects an "overlay": bytes appended to a PE file after the region the Authenticode signature
/// covers (the end of the certificate table, or the last section for unsigned files). A signed
/// binary with a large overlay can be a stuffed/trojanized build — WinVerifyTrust still says valid
/// because the appended bytes are outside the signed range. Reported as a signal, not a verdict
/// (installers/SFX legitimately carry an overlay). BCL-only, local, zero quota.
/// </summary>
internal static class OverlayDetector
{
    /// <summary>Number of bytes after the signed/section region, or 0 if none / not a PE / on error.</summary>
    public static long OverlayBytes(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            long fileLen = fs.Length;
            using var pe = new PEReader(fs);

            long signedEnd;
            var certDir = pe.PEHeaders.PEHeader?.CertificateTableDirectory ?? default;
            if (certDir.Size > 0)
            {
                // The certificate table directory's "RVA" is actually a file offset.
                signedEnd = (long)certDir.RelativeVirtualAddress + certDir.Size;
            }
            else
            {
                long max = 0;
                foreach (var s in pe.PEHeaders.SectionHeaders)
                    max = Math.Max(max, (long)s.PointerToRawData + s.SizeOfRawData);
                signedEnd = max;
            }

            long overlay = fileLen - signedEnd;
            return overlay > 0 ? overlay : 0;
        }
        catch { return 0; }
    }
}
