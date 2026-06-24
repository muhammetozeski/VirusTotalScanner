using System.Buffers;
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

        byte[] buffer = ArrayPool<byte>.Shared.Rent(1 << 20); // pooled: avoids a per-file LOH allocation
        try
        {
            int read;
            while ((read = await fs.ReadAsync(buffer, ct)) > 0)
            {
                md5.AppendData(buffer, 0, read);
                sha.AppendData(buffer, 0, read);
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }

        string md5Hex = Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant();
        string shaHex = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
        return (md5Hex, shaHex);
    }

    /// <summary>MD5 only, single pass — for cache-existence peeks (timeline / downloads triage) where
    /// the SHA-256 from <see cref="ComputeAsync"/> would be computed and immediately thrown away.</summary>
    public static async Task<string> ComputeMd5Async(string path, CancellationToken ct = default)
    {
        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, useAsync: true);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(1 << 20); // pooled: avoids a per-file LOH allocation
        try
        {
            int read;
            while ((read = await fs.ReadAsync(buffer, ct)) > 0)
                md5.AppendData(buffer, 0, read);
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }

        return Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant();
    }

    public readonly record struct HashCheck(bool Matched, string Algorithm, string Actual, string Expected);

    /// <summary>
    /// Verifies a file against a user-supplied expected hash. The algorithm is chosen by the
    /// expected hash length (32=MD5, 40=SHA-1, 64=SHA-256); all three are computed in one pass so a
    /// mismatch can still report the file's real hash. Non-hex characters in the input are ignored.
    /// </summary>
    public static async Task<HashCheck> VerifyExpectedAsync(string path, string expected, CancellationToken ct = default)
    {
        string exp = new string((expected ?? "").Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();

        using var md5 = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        using var sha1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, useAsync: true);

        byte[] buffer = ArrayPool<byte>.Shared.Rent(1 << 20); // pooled: avoids a per-file LOH allocation
        try
        {
            int read;
            while ((read = await fs.ReadAsync(buffer, ct)) > 0)
            {
                md5.AppendData(buffer, 0, read);
                sha1.AppendData(buffer, 0, read);
                sha.AppendData(buffer, 0, read);
            }
        }
        finally { ArrayPool<byte>.Shared.Return(buffer); }

        string m = Convert.ToHexString(md5.GetHashAndReset()).ToLowerInvariant();
        string s1 = Convert.ToHexString(sha1.GetHashAndReset()).ToLowerInvariant();
        string s256 = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();

        (string algo, string actual) = exp.Length switch
        {
            32 => ("MD5", m),
            40 => ("SHA-1", s1),
            64 => ("SHA-256", s256),
            _ => ("?", s256),
        };
        bool matched = exp.Length is 32 or 40 or 64 && string.Equals(actual, exp, StringComparison.Ordinal);
        return new HashCheck(matched, algo, actual, exp);
    }
}
