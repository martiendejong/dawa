using System.Numerics;
using System.Security.Cryptography;

namespace Dawa.Crypto;

/// <summary>
/// XEdDSA signing (Signal/WhatsApp protocol).
/// Uses a raw Curve25519 private key directly as an Ed25519 scalar —
/// no SHA-512 key-expansion like standard Ed25519.
/// Reference: https://signal.org/docs/specifications/xeddsa/
/// Matches curve25519-js curve25519_sign() behaviour used by Baileys.
/// </summary>
public static class XEdDSA
{
    // ─── Ed25519 constants ────────────────────────────────────────────────

    // Field prime p = 2^255 - 19
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

    // Group order l = 2^252 + 27742317777372353535851937790883648493
    private static readonly BigInteger L =
        BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

    // Curve constant d = -121665/121666 mod p
    private static readonly BigInteger D;

    // Base point G (affine)
    private static readonly (BigInteger X, BigInteger Y) G;

    static XEdDSA()
    {
        D = Fp(-121665 * FpInv(121666));

        // Base point: Gy = 4/5 mod p, Gx = positive square root of (Gy²-1)/(d·Gy²+1)
        var Gy  = Fp(4 * FpInv(5));
        var Gy2 = Fp(Gy * Gy);
        var Gx2 = Fp((Gy2 - 1) * FpInv(Fp(D * Gy2 + 1)));
        var Gx  = FpSqrt(Gx2);
        if (!Gx.IsEven) Gx = P - Gx; // choose positive root (even)
        G = (Gx, Gy);
    }

    // ─── Public API ───────────────────────────────────────────────────────

    /// <summary>
    /// Verifies an XEdDSA signature.
    /// <paramref name="curve25519PublicKey"/> is the 32-byte Curve25519 (Montgomery x) public key.
    /// </summary>
    public static bool Verify(byte[] curve25519PublicKey, byte[] message, byte[] signature)
    {
        if (signature.Length != 64) return false;

        // 1. Convert Curve25519 Montgomery x → Edwards y:  y = (u-1)/(u+1) mod p
        var u  = LoadLE(curve25519PublicKey);
        var y  = Fp((u - 1) * FpInv(u + 1));

        // 2. Recover Edwards x from y (positive/even root)
        var y2 = Fp(y * y);
        var x2 = Fp((y2 - 1) * FpInv(Fp(D * y2 + 1)));
        var ax  = FpSqrt(x2);
        if (!ax.IsEven) ax = P - ax;
        var A = (ax, y);
        var Ap = PackPoint(A);

        // 3. Parse R (packed point) and s from signature
        var Rp    = signature[0..32];
        var sBuf  = signature[32..64];
        var s     = LoadLE(sBuf);
        if (s >= L) return false;

        // 4. Unpack R
        var Rbuf  = (byte[])Rp.Clone();
        var Rsign = (Rbuf[31] & 0x80) != 0;
        Rbuf[31] &= 0x7F;
        var Ry  = LoadLE(Rbuf);
        var Ry2 = Fp(Ry * Ry);
        var Rx2 = Fp((Ry2 - 1) * FpInv(Fp(D * Ry2 + 1)));
        var Rx  = FpSqrt(Rx2);
        if (Rsign != !Rx.IsEven) Rx = P - Rx;
        var R = (Rx, Ry);

        // 5. h = SHA-512(R ‖ A ‖ message) mod l
        var hHash = SHA512.HashData([.. Rp, .. Ap, .. message]);
        var h     = Fl(LoadLE64(hHash));

        // 6. s·G == R + h·A
        var lhs = PointMult(G, s);
        var rhs = PointAdd(R, PointMult(A, h));
        return lhs.X == rhs.X && lhs.Y == rhs.Y;
    }

    /// <summary>
    /// Signs <paramref name="message"/> using XEdDSA with the given 32-byte
    /// Curve25519 private key. Returns a 64-byte signature (R ‖ s).
    /// </summary>
    public static byte[] Sign(byte[] privateKey, byte[] message)
    {
        // 1. Clamp Curve25519 private key → Ed25519 scalar a
        var aClamped = (byte[])privateKey.Clone();
        aClamped[0] &= 248; aClamped[31] &= 127; aClamped[31] |= 64;
        var aInt = LoadLE(aClamped);

        // 2. A = a × G  (Ed25519 public key derived from the scalar)
        var A = PointMult(G, aInt);

        // 3. XEdDSA sign convention: A must have a non-negative (even) x-coordinate.
        //    Verifiers recover A from the Curve25519 key using always the positive x root.
        //    If our A.x is negative (odd), negate the scalar so A becomes -A (same y, flipped x).
        if (!A.X.IsEven)
        {
            aInt = Fl(L - aInt);          // negate scalar mod l
            A    = (Fp(P - A.X), A.Y);   // flip x sign (same point, opposite x sign)
        }
        var Ap = PackPoint(A); // bit 255 of Ap is now always 0

        // 4. r = SHA-512(a ‖ message ‖ Z) mod l  (Signal XEdDSA nonce, using final scalar)
        var aBytes = ToLE32(aInt);
        var Z      = System.Security.Cryptography.RandomNumberGenerator.GetBytes(64);
        var rHash  = SHA512.HashData([.. aBytes, .. message, .. Z]);
        var r     = Fl(LoadLE64(rHash));

        // 5. R = r × G
        var R  = PointMult(G, r);
        var Rp = PackPoint(R);

        // 6. h = SHA-512(R ‖ A ‖ message) mod l
        var hHash = SHA512.HashData([.. Rp, .. Ap, .. message]);
        var h     = Fl(LoadLE64(hHash));

        // 7. s = (r + h·a) mod l
        var s = Fl(r + h * aInt);

        // 8. Signature = R (32 bytes) ‖ s (32 bytes)
        var sig = new byte[64];
        Rp.CopyTo(sig, 0);
        ToLE32(s).CopyTo(sig, 32);
        return sig;
    }

    // ─── Ed25519 group operations (affine coords) ─────────────────────────

    private static (BigInteger X, BigInteger Y) PointMult(
        (BigInteger X, BigInteger Y) pt, BigInteger n)
    {
        var Q = (X: BigInteger.Zero, Y: BigInteger.One); // identity element
        while (n > 0)
        {
            if (!n.IsEven) Q = PointAdd(Q, pt);
            pt = PointAdd(pt, pt);
            n >>= 1;
        }
        return Q;
    }

    private static (BigInteger X, BigInteger Y) PointAdd(
        (BigInteger X, BigInteger Y) p1, (BigInteger X, BigInteger Y) p2)
    {
        // Twisted Edwards: -x² + y² = 1 + d·x²·y²
        // Addition formulas (a=-1):
        //   x3 = (x1·y2 + y1·x2) / (1 + d·x1·x2·y1·y2)
        //   y3 = (y1·y2 + x1·x2) / (1 - d·x1·x2·y1·y2)
        var x1x2 = Fp(p1.X * p2.X);
        var y1y2 = Fp(p1.Y * p2.Y);
        var dxy  = Fp(D * Fp(x1x2 * y1y2));
        var x3   = Fp(Fp(p1.X * p2.Y + p1.Y * p2.X) * FpInv(Fp(1 + dxy)));
        var y3   = Fp(Fp(y1y2 + x1x2)                * FpInv(Fp(1 - dxy)));
        return (x3, y3);
    }

    private static byte[] PackPoint((BigInteger X, BigInteger Y) pt)
    {
        var y = ToLE32(pt.Y);
        // High bit of last byte = sign of x (x is "negative" if odd)
        if (!pt.X.IsEven) y[31] |= 0x80;
        return y;
    }

    // ─── Field arithmetic (mod p) ─────────────────────────────────────────

    /// <summary>Reduce a to [0, p).</summary>
    private static BigInteger Fp(BigInteger a) => ((a % P) + P) % P;

    /// <summary>Modular inverse via Fermat: a^(p-2) mod p.</summary>
    private static BigInteger FpInv(BigInteger a) => BigInteger.ModPow(Fp(a), P - 2, P);

    /// <summary>Square root mod p (p ≡ 5 mod 8).</summary>
    private static BigInteger FpSqrt(BigInteger a)
    {
        var r = BigInteger.ModPow(a, (P + 3) / 8, P);
        if (Fp(r * r) != Fp(a))
        {
            var sqrt_minus1 = BigInteger.ModPow(2, (P - 1) / 4, P);
            r = Fp(r * sqrt_minus1);
        }
        return r;
    }

    /// <summary>Reduce a to [0, l) (scalar field).</summary>
    private static BigInteger Fl(BigInteger a) => ((a % L) + L) % L;

    // ─── Encoding helpers ─────────────────────────────────────────────────

    /// <summary>Load a little-endian unsigned 32-byte array as BigInteger.</summary>
    private static BigInteger LoadLE(byte[] b)
    {
        Span<byte> tmp = stackalloc byte[33];
        b.CopyTo(tmp);
        tmp[32] = 0; // ensure positive
        return new BigInteger(tmp);
    }

    /// <summary>Load a little-endian unsigned 64-byte array as BigInteger.</summary>
    private static BigInteger LoadLE64(byte[] b)
    {
        Span<byte> tmp = stackalloc byte[65];
        b.CopyTo(tmp);
        tmp[64] = 0;
        return new BigInteger(tmp);
    }

    /// <summary>Store BigInteger as 32-byte little-endian array.</summary>
    private static byte[] ToLE32(BigInteger n)
    {
        var src = n.ToByteArray(); // little-endian, may have extra sign byte
        var dst = new byte[32];
        var len = Math.Min(src.Length, 32);
        src.AsSpan(0, len).CopyTo(dst);
        return dst;
    }
}
