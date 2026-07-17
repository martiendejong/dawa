using Dawa.Binary;
using Xunit;

namespace Dawa.Tests;

/// <summary>
/// Encode → decode round-trip tests for the WhatsApp binary node codec. The complete
/// Dawa handles the transport flag byte at the socket layer, so the encoder/decoder
/// operate on raw node bytes; these tests exercise that raw codec directly.
/// </summary>
public class BinaryTests
{
    private static string? AsString(object? content) =>
        content is byte[] b ? System.Text.Encoding.UTF8.GetString(b) : content as string;

    [Fact]
    public void RoundTrip_RawStrings_AndAttributes()
    {
        var node = new BinaryNode(
            "zzz_custom_tag",
            new() { ["zzz_attr_a"] = "value-1234", ["zzz_attr_b"] = "another+value" },
            "zzz_text_content");

        var decoded = BinaryNodeDecoder.Decode(BinaryNodeEncoder.Encode(node));

        Assert.Equal(node.Tag, decoded.Tag);
        Assert.Equal("value-1234", decoded.Attrs["zzz_attr_a"]);
        Assert.Equal("another+value", decoded.Attrs["zzz_attr_b"]);
        Assert.Equal("zzz_text_content", AsString(decoded.Content));
    }

    [Fact]
    public void RoundTrip_DictionaryTokens()
    {
        // "iq", "type", "id" etc. are real WhatsApp tokens — must survive tokenised.
        var node = new BinaryNode("iq",
            new() { ["type"] = "result", ["id"] = "ABC123", ["xmlns"] = "md" });

        var decoded = BinaryNodeDecoder.Decode(BinaryNodeEncoder.Encode(node));

        Assert.Equal("iq", decoded.Tag);
        Assert.Equal("result", decoded.Attrs["type"]);
        Assert.Equal("ABC123", decoded.Attrs["id"]);
        Assert.Equal("md", decoded.Attrs["xmlns"]);
    }

    [Fact]
    public void RoundTrip_NestedChildNodes()
    {
        var child1 = new BinaryNode("ref", null, System.Text.Encoding.UTF8.GetBytes("REF-TOKEN-1"));
        var child2 = new BinaryNode("ref", null, System.Text.Encoding.UTF8.GetBytes("REF-TOKEN-2"));
        var parent = new BinaryNode("pair-device", null, new List<BinaryNode> { child1, child2 });
        var root = new BinaryNode("iq", new() { ["type"] = "set" }, new List<BinaryNode> { parent });

        var decoded = BinaryNodeDecoder.Decode(BinaryNodeEncoder.Encode(root));

        Assert.Equal("iq", decoded.Tag);
        var pd = decoded.FindChild("pair-device");
        Assert.NotNull(pd);
        var refs = pd!.GetChildren("ref").ToList();
        Assert.Equal(2, refs.Count);
        Assert.Equal("REF-TOKEN-1", AsString(refs[0].Content));
        Assert.Equal("REF-TOKEN-2", AsString(refs[1].Content));
    }

    [Fact]
    public void RoundTrip_JidAttribute()
    {
        var node = new BinaryNode("message",
            new() { ["from"] = "31612345678@s.whatsapp.net", ["to"] = "@s.whatsapp.net" });

        var decoded = BinaryNodeDecoder.Decode(BinaryNodeEncoder.Encode(node));

        Assert.Equal("31612345678@s.whatsapp.net", decoded.Attrs["from"]);
        Assert.Equal("@s.whatsapp.net", decoded.Attrs["to"]);
    }

    [Fact]
    public void RoundTrip_BinaryContent_Preserved()
    {
        var payload = new byte[300];
        new Random(42).NextBytes(payload); // >255 forces the 20-bit length path
        var node = new BinaryNode("enc", new() { ["type"] = "pkmsg" }, payload);

        var decoded = BinaryNodeDecoder.Decode(BinaryNodeEncoder.Encode(node));
        Assert.Equal(payload, decoded.Data);
    }

    [Fact]
    public void TokenTables_HaveExpectedShape()
    {
        // Regenerated verbatim from Baileys: 236 single-byte, 4×256 double-byte.
        Assert.Equal(236, WATags.SingleByteTokens.Length);
        Assert.Equal(4, WATags.AllDictionaries.Length);
        Assert.All(WATags.AllDictionaries, d => Assert.Equal(256, d.Length));
        // Spot-check known indices used during pairing.
        Assert.Equal("iq", WATags.SingleByteTokens[25]);
        Assert.Equal("s.whatsapp.net", WATags.SingleByteTokens[3]);
    }
}
