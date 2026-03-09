using System.Security.Cryptography;

namespace Dawa.Crypto;

/// <summary>HMAC-based Key Derivation Function (RFC 5869).</summary>
public static class DawaHKDF
{
    /// <summary>
    /// Derives one or more keys from input key material using HKDF-SHA256.
    /// </summary>
    public static byte[] DeriveKey(byte[] inputKeyMaterial, byte[] salt, byte[]? info = null, int outputLength = 32)
    {
        // Extract
        var prk = HMACSHA256.HashData(salt, inputKeyMaterial);

        // Expand
        var infoBytes = info ?? Array.Empty<byte>();
        var output = new byte[outputLength];
        var t = Array.Empty<byte>();
        var written = 0;
        byte counter = 1;

        while (written < outputLength)
        {
            var block = new byte[t.Length + infoBytes.Length + 1];
            t.CopyTo(block, 0);
            infoBytes.CopyTo(block, t.Length);
            block[^1] = counter++;
            t = HMACSHA256.HashData(prk, block);
            var take = Math.Min(t.Length, outputLength - written);
            t.AsSpan(0, take).CopyTo(output.AsSpan(written));
            written += take;
        }
        return output;
    }

    /// <summary>Derives exactly two 32-byte keys (common in Noise protocol).</summary>
    public static (byte[] k1, byte[] k2) DeriveKeys(byte[] inputKeyMaterial, byte[] salt)
    {
        var raw = DeriveKey(inputKeyMaterial, salt, null, 64);
        return (raw[..32], raw[32..]);
    }
}
