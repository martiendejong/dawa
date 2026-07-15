using System.Numerics;
using Dawa.Crypto;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Xunit;

namespace Dawa.Tests;

/// <summary>
/// Proves Dawa's XEdDSA signatures are VALID under an independent verifier — the
/// same check WhatsApp runs server-side on the signed pre-key during registration
/// (869e513va). This is the gap the earlier SignedPreKey test left open: that test
/// only proved Dawa signs the right MESSAGE with its own Sign; it did not prove the
/// signature actually verifies.
///
/// Independence: the Edwards public key A is reconstructed from the Montgomery
/// public key via the standard birational map y = (u-1)/(u+1) with sign bit 0
/// (exactly what a verifier that only holds the Curve25519 public key does), and the
/// signature is checked with BouncyCastle's Ed25519 (not Dawa's own point math).
///
/// XEdDSA sign requires forcing A's sign bit to 0; if that is skipped, ~half of all
/// identity keys produce a signature that fails this verification — hence the loop
/// over many random keys.
/// </summary>
public class XEdDSASignatureTests
{
    // p = 2^255 - 19
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    [Fact]
    public void XEdDSA_Signatures_VerifyUnderIndependentEd25519_AcrossManyKeys()
    {
        const int keys = 64; // ~half would fail if the sign bit weren't forced to 0
        for (var i = 0; i < keys; i++)
        {
            var (priv, montPub) = Curve25519Helper.GenerateKeyPair();
            var message = System.Text.Encoding.UTF8.GetBytes($"signed pre-key material #{i}");

            var sig = XEdDSA.Sign(priv, message);
            var edPub = MontgomeryPublicKeyToEd25519(montPub); // verifier's reconstruction, sign bit 0

            var ok = Ed25519.Verify(sig, 0, edPub, 0, message, 0, message.Length);
            Assert.True(ok, $"XEdDSA signature failed independent Ed25519 verification for key #{i}");
        }
    }

    /// <summary>
    /// Reconstruct the Ed25519 public key a verifier uses from a Curve25519 (Montgomery
    /// u) public key: y = (u-1)/(u+1) mod p, packed little-endian with sign bit 0.
    /// </summary>
    private static byte[] MontgomeryPublicKeyToEd25519(byte[] montPub)
    {
        var u = LoadLE(montPub) % P;            // X25519 pubkeys have byte31 high bit unset
        var num = (u - 1 + P) % P;
        var den = (u + 1) % P;
        var y = (num * BigInteger.ModPow(den, P - 2, P)) % P; // (u-1)/(u+1) mod p

        var packed = ToLE32(y);
        packed[31] &= 0x7F; // sign bit 0
        return packed;
    }

    private static BigInteger LoadLE(byte[] b)
    {
        var clean = (byte[])b.Clone();
        if (clean.Length >= 32) clean[31] &= 0x7F; // mask the (unused) high bit
        var tmp = new byte[clean.Length + 1];
        Array.Copy(clean, tmp, clean.Length);      // trailing zero ⇒ positive BigInteger
        return new BigInteger(tmp);
    }

    private static byte[] ToLE32(BigInteger n)
    {
        var src = n.ToByteArray(); // little-endian, possibly with a sign byte
        var dst = new byte[32];
        Array.Copy(src, dst, Math.Min(src.Length, 32));
        return dst;
    }
}
