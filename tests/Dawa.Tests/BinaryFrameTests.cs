using Dawa.Binary;
using Xunit;

namespace Dawa.Tests;

/// <summary>
/// WhatsApp frames a binary node as [1 flag byte][node bytes] (flag bit 0x02 = zlib).
/// Dawa's decoder previously read from byte 0, treating the flag byte as part of the
/// node and desyncing one byte in ("Unexpected string tag: F8" on the pair-device
/// frame, 869e51uxu). These tests lock the flag-byte handling on both encode + decode.
/// </summary>
public class BinaryFrameTests
{
    [Fact]
    public void EncodeThenDecode_RoundTrips_ThroughTheFlagByte()
    {
        // Strings deliberately NOT in the token dictionary so they take the raw
        // length-prefixed path — this isolates the flag-byte framing.
        var node = new BinaryNode(
            "zzz_custom_tag",
            new Dictionary<string, string>
            {
                ["zzz_attr_one"] = "value-1234",
                ["zzz_attr_two"] = "another+value",
            },
            "zzz_text_content");

        var encoded = BinaryNodeEncoder.Encode(node);

        Assert.Equal(0x00, encoded[0]); // leading uncompressed flag byte

        var decoded = BinaryNodeDecoder.Decode(encoded);
        Assert.Equal(node.Tag, decoded.Tag);
        Assert.Equal("value-1234", decoded.Attrs["zzz_attr_one"]);
        Assert.Equal("another+value", decoded.Attrs["zzz_attr_two"]);
        // Content shares a tag between "string" and "binary" in the WA wire format, so
        // it may come back as bytes; normalise for this flag-byte round-trip check.
        var content = decoded.Content is byte[] bytes
            ? System.Text.Encoding.UTF8.GetString(bytes)
            : decoded.Content as string;
        Assert.Equal("zzz_text_content", content);
    }

    [Fact]
    public void Decode_EmptyFrame_Throws()
    {
        Assert.Throws<InvalidDataException>(() => BinaryNodeDecoder.Decode([]));
    }
}
