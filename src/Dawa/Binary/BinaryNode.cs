using System.Text;

namespace Dawa.Binary;

/// <summary>
/// WhatsApp binary node — the base unit of the WhatsApp XML-like binary protocol.
/// Equivalent to Baileys' BinaryNode type.
/// </summary>
public sealed class BinaryNode
{
    /// <summary>The tag name (e.g. "message", "iq", "presence").</summary>
    public string Tag { get; set; } = "";

    /// <summary>Attributes as key-value pairs.</summary>
    public Dictionary<string, string> Attrs { get; set; } = new();

    /// <summary>Child nodes, raw byte data, or null.</summary>
    public object? Content { get; set; }

    public BinaryNode() { }

    public BinaryNode(string tag, Dictionary<string, string>? attrs = null, object? content = null)
    {
        Tag = tag;
        Attrs = attrs ?? new();
        Content = content;
    }

    /// <summary>Returns child nodes if Content is a list, else empty.</summary>
    public IReadOnlyList<BinaryNode> Children =>
        Content is List<BinaryNode> nodes ? nodes : [];

    /// <summary>Returns raw byte content if Content is byte[], else null.</summary>
    public byte[]? Data =>
        Content as byte[];

    /// <summary>Returns string content if Content is string, else null.</summary>
    public string? Text =>
        Content as string;

    /// <summary>Gets an attribute value or null.</summary>
    public string? GetAttr(string key) =>
        Attrs.TryGetValue(key, out var v) ? v : null;

    /// <summary>Recursively finds the first child with the given tag.</summary>
    public BinaryNode? FindChild(string tag) =>
        Children.FirstOrDefault(c => c.Tag == tag);

    /// <summary>All children with the given tag.</summary>
    public IEnumerable<BinaryNode> GetChildren(string tag) =>
        Children.Where(c => c.Tag == tag);

    public override string ToString()
    {
        var sb = new StringBuilder();
        sb.Append($"<{Tag}");
        foreach (var (k, v) in Attrs)
            sb.Append($" {k}=\"{v}\"");
        if (Content == null)
        {
            sb.Append("/>");
        }
        else if (Content is List<BinaryNode> children)
        {
            sb.Append(">");
            foreach (var c in children) sb.Append(c);
            sb.Append($"</{Tag}>");
        }
        else if (Content is byte[] data)
        {
            sb.Append($">[{data.Length} bytes]</{Tag}>");
        }
        else
        {
            sb.Append($">{Content}</{Tag}>");
        }
        return sb.ToString();
    }
}
