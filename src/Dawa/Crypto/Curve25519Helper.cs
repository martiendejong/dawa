using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Dawa.Crypto;

/// <summary>
/// Curve25519 key generation and ECDH shared secret computation via BouncyCastle.
/// </summary>
public static class Curve25519Helper
{
    private static readonly SecureRandom _rng = new();

    /// <summary>Generates a new random Curve25519 key pair.</summary>
    public static (byte[] privateKey, byte[] publicKey) GenerateKeyPair()
    {
        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(_rng));
        var kp = generator.GenerateKeyPair();

        var priv = new byte[32];
        var pub = new byte[32];
        ((X25519PrivateKeyParameters)kp.Private).Encode(priv, 0);
        ((X25519PublicKeyParameters)kp.Public).Encode(pub, 0);
        return (priv, pub);
    }

    /// <summary>Computes the Curve25519 ECDH shared secret.</summary>
    public static byte[] DH(byte[] privateKey, byte[] publicKey)
    {
        var privParam = new X25519PrivateKeyParameters(privateKey, 0);
        var pubParam = new X25519PublicKeyParameters(publicKey, 0);
        var agreement = new X25519Agreement();
        agreement.Init(privParam);
        var shared = new byte[32];
        agreement.CalculateAgreement(pubParam, shared, 0);
        return shared;
    }
}
