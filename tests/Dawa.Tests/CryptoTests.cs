using System.Security.Cryptography;
using Dawa.Auth;
using Dawa.Crypto;
using Dawa.Noise;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;

namespace Dawa.Tests;

/// <summary>
/// Deterministic, offline tests of Dawa's cryptographic primitives — the layers a
/// live WhatsApp handshake depends on. This is the complete (live-verified) Dawa, so
/// these lock in behaviour that is already known to pair against production.
/// </summary>
public class CryptoTests
{
    // ── XEdDSA: sign then verify, both with Dawa's own Verify and independently ──
    [Fact]
    public void XEdDSA_SignVerify_RoundTrips_AcrossManyKeys()
    {
        for (var i = 0; i < 32; i++)
        {
            var (priv, pub) = Curve25519Helper.GenerateKeyPair();
            var msg = System.Text.Encoding.UTF8.GetBytes($"message {i}");
            var sig = XEdDSA.Sign(priv, msg);

            Assert.Equal(64, sig.Length);
            Assert.True(XEdDSA.Verify(pub, msg, sig), $"Dawa.Verify rejected its own signature (key {i})");
            // Tampered message must fail.
            var bad = (byte[])msg.Clone(); bad[0] ^= 0xFF;
            Assert.False(XEdDSA.Verify(pub, bad, sig));
        }
    }

    // ── XEdDSA signatures verify under an INDEPENDENT Ed25519 verifier ──
    // This is the exact check WhatsApp runs on the signed pre-key at registration.
    // Reconstruct the Edwards key from the Montgomery key with sign bit 0.
    [Fact]
    public void XEdDSA_Signatures_VerifyUnderIndependentEd25519()
    {
        var p = System.Numerics.BigInteger.Pow(2, 255) - 19;
        for (var i = 0; i < 32; i++)
        {
            var (priv, montPub) = Curve25519Helper.GenerateKeyPair();
            var msg = System.Text.Encoding.UTF8.GetBytes($"prekey material {i}");
            var sig = XEdDSA.Sign(priv, msg);

            // y = (u-1)/(u+1) mod p, packed little-endian, sign bit 0.
            var u = LoadLE(montPub) % p;
            var y = ((u - 1 + p) % p) * System.Numerics.BigInteger.ModPow((u + 1) % p, p - 2, p) % p;
            var edPub = ToLE32(y); edPub[31] &= 0x7F;

            Assert.True(Ed25519.Verify(sig, 0, edPub, 0, msg, 0, msg.Length),
                $"XEdDSA signature failed independent Ed25519 verification (key {i})");
        }
    }

    // ── AES-GCM counter transport: roundtrip + tamper detection ──
    [Fact]
    public void AesGcm_CounterRoundtrips_AndDetectsTampering()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var pt = System.Text.Encoding.UTF8.GetBytes("transport frame payload");
        var aad = System.Text.Encoding.UTF8.GetBytes("hash");

        var ct = AesGcmHelper.EncryptWithCounter(key, 5, pt, aad);
        Assert.Equal(pt, AesGcmHelper.DecryptWithCounter(key, 5, ct, aad));

        // Wrong counter and tampered ciphertext must both fail authentication.
        Assert.ThrowsAny<CryptographicException>(() => AesGcmHelper.DecryptWithCounter(key, 6, ct, aad));
        var bad = (byte[])ct.Clone(); bad[0] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(() => AesGcmHelper.DecryptWithCounter(key, 5, bad, aad));
    }

    [Fact]
    public void AesGcm_NoncePrefixAndRaw_Roundtrip()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var pt = System.Text.Encoding.UTF8.GetBytes("hello");

        var withPrefix = AesGcmHelper.Encrypt(key, pt);            // nonce(12)+ct+tag
        Assert.Equal(pt, AesGcmHelper.DecryptWithNoncePrefix(key, withPrefix));

        var nonce = RandomNumberGenerator.GetBytes(12);
        var raw = AesGcmHelper.EncryptRaw(key, nonce, pt);
        Assert.Equal(pt, AesGcmHelper.DecryptRaw(key, nonce, raw));
    }

    // ── HKDF: deterministic, and DeriveKeys splits the 64-byte output in order ──
    [Fact]
    public void Hkdf_IsDeterministic_AndSplitsInOrder()
    {
        var ikm = RandomNumberGenerator.GetBytes(32);
        var salt = RandomNumberGenerator.GetBytes(32);

        Assert.Equal(DawaHKDF.DeriveKey(ikm, salt, null, 64), DawaHKDF.DeriveKey(ikm, salt, null, 64));

        var full = DawaHKDF.DeriveKey(ikm, salt, null, 64);
        var (first, second) = DawaHKDF.DeriveKeys(ikm, salt);
        Assert.Equal(full[..32], first);
        Assert.Equal(full[32..], second);
    }

    // ── Curve25519 DH agreement (both sides derive the same shared secret) ──
    [Fact]
    public void Curve25519_DH_Agrees()
    {
        var (aPriv, aPub) = Curve25519Helper.GenerateKeyPair();
        var (bPriv, bPub) = Curve25519Helper.GenerateKeyPair();
        Assert.Equal(Curve25519Helper.DH(aPriv, bPub), Curve25519Helper.DH(bPriv, aPub));
    }

    // ── NoiseState.MixKey: two parties with the same input derive matching keys ──
    [Fact]
    public void NoiseMixKey_TwoParties_AgreeOnTransport()
    {
        var ikm = RandomNumberGenerator.GetBytes(32);
        var aad = RandomNumberGenerator.GetBytes(16);
        var a = new NoiseState();
        var b = new NoiseState();
        a.MixHash(aad); b.MixHash(aad);
        a.MixKey(ikm);  b.MixKey(ikm);

        var pt = System.Text.Encoding.UTF8.GetBytes("mutual key check");
        var ct = a.EncryptWithAssociatedData(pt);
        Assert.Equal(pt, b.DecryptWithAssociatedData(ct));
    }

    // ── AuthState.CreateNew: the signed pre-key it generates actually verifies ──
    // This is what the server checks during registration; the live pairing proves it,
    // this locks it offline.
    [Fact]
    public void AuthState_SignedPreKey_Verifies()
    {
        var s = AuthState.CreateNew();
        Assert.Equal(32, s.SignedPreKeyPublic.Length);
        Assert.Equal(64, s.SignedPreKeySignature.Length);

        // Signature is over the 0x05-prefixed key; verify with Dawa's own Verify against
        // the identity public key.
        Assert.True(XEdDSA.Verify(s.SignedIdentityKeyPublic, Prefix05(s.SignedPreKeyPublic), s.SignedPreKeySignature));
    }

    private static byte[] Prefix05(byte[] pub)
    {
        var m = new byte[33]; m[0] = 0x05; pub.CopyTo(m, 1); return m;
    }

    private static System.Numerics.BigInteger LoadLE(byte[] b)
    {
        var c = (byte[])b.Clone(); if (c.Length >= 32) c[31] &= 0x7F;
        var t = new byte[c.Length + 1]; Array.Copy(c, t, c.Length);
        return new System.Numerics.BigInteger(t);
    }

    private static byte[] ToLE32(System.Numerics.BigInteger n)
    {
        var src = n.ToByteArray(); var dst = new byte[32];
        Array.Copy(src, dst, Math.Min(src.Length, 32)); return dst;
    }
}
