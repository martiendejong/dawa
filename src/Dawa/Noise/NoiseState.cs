using System.Security.Cryptography;
using System.Text;
using Dawa.Crypto;

namespace Dawa.Noise;

/// <summary>
/// Implements the Noise_XX_25519_AESGCM_SHA256 state machine used by WhatsApp.
/// Reference: https://noiseprotocol.org/noise.html
/// </summary>
public sealed class NoiseState
{
    // Protocol name padded to 32 bytes
    private const string ProtocolName = "Noise_XX_25519_AESGCM_SHA256";

    // h = hash, ck = chaining key, k = cipher key
    private byte[] _h;
    private byte[] _ck;
    private byte[] _k = new byte[32];
    private ulong _n = 0;

    public NoiseState()
    {
        // Initialize h and ck to SHA256 of the protocol name (padded to 32 bytes)
        var name = Encoding.ASCII.GetBytes(ProtocolName);
        var padded = new byte[32];
        if (name.Length <= 32)
            name.CopyTo(padded, 0);
        else
            padded = SHA256.HashData(name);

        _h = (byte[])padded.Clone();
        _ck = (byte[])padded.Clone();
    }

    /// <summary>Mixes data into the hash chain (no encryption).</summary>
    public void MixHash(byte[] data)
    {
        _h = SHA256.HashData([.. _h, .. data]);
    }

    /// <summary>Mixes input key material into the chaining key and optionally sets a new cipher key.</summary>
    public void MixKey(byte[] inputKeyMaterial)
    {
        var (ck, k) = DawaHKDF.DeriveKeys(inputKeyMaterial, _ck);
        _ck = ck;
        _k = k;
        _n = 0;
    }

    /// <summary>Encrypts plaintext with the current key + associated data = current hash.</summary>
    public byte[] EncryptWithAssociatedData(byte[] plaintext)
    {
        if (IsKeyEmpty()) return plaintext;
        var ct = AesGcmHelper.EncryptWithCounter(_k, _n++, plaintext, _h);
        MixHash([.. plaintext]);
        // Actually: MixHash the ciphertext per Noise spec
        MixHash(ct);
        return ct;
    }

    /// <summary>Decrypts ciphertext with the current key + associated data = current hash.</summary>
    public byte[] DecryptWithAssociatedData(byte[] ciphertext)
    {
        if (IsKeyEmpty()) return ciphertext;
        var pt = AesGcmHelper.DecryptWithCounter(_k, _n++, ciphertext, _h);
        MixHash(ciphertext);
        return pt;
    }

    /// <summary>
    /// Finalises the handshake and returns the two transport keys (send, receive).
    /// </summary>
    public (byte[] sendKey, byte[] recvKey) Split()
    {
        var (k1, k2) = DawaHKDF.DeriveKeys(Array.Empty<byte>(), _ck);
        return (k1, k2);
    }

    public byte[] Hash => (byte[])_h.Clone();
    public byte[] ChainingKey => (byte[])_ck.Clone();

    private bool IsKeyEmpty() => _k.All(b => b == 0);
}
