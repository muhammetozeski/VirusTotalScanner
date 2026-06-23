using System.Security.Cryptography;

namespace VirusTotalScanner;

/// <summary>Computes MD5 (existence check, per requirement) and SHA-256 (report id) in one pass.</summary>
internal static class HashService
{
    public static async Task<(string Md5, string Sha256)> ComputeAsync(string path, CancellationToken ct = default)
    {
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, useAsync: true);

        byte[] buffer = new byte[1 << 20];
        int read;
        while ((read = await fs.ReadAsync(buffer, ct)) > 0)
        {
            md5.AppendData(buffer, 0, read);
            sha.AppendData(buffer, 0, read);
        }

        string md5Hex = Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant();
        string shaHex = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
        return (md5Hex, shaHex);
    }
}
