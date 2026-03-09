using System.Text;

namespace Dawa.Binary;

/// <summary>
/// Encodes BinaryNode trees to WhatsApp's binary format.
/// </summary>
public static class BinaryNodeEncoder
{
    public static byte[] Encode(BinaryNode node)
    {
        var ms = new MemoryStream();
        WriteNode(ms, node);
        return ms.ToArray();
    }

    private static void WriteNode(Stream s, BinaryNode node)
    {
        // Determine list size = 1 (tag) + 2*attrs + (1 if has content)
        int listSize = 1 + (node.Attrs.Count * 2) + (node.Content != null ? 1 : 0);
        WriteListSize(s, listSize);
        WriteString(s, node.Tag);

        foreach (var (k, v) in node.Attrs)
        {
            WriteString(s, k);
            WriteString(s, v);
        }

        if (node.Content is List<BinaryNode> children)
        {
            WriteListSize(s, children.Count);
            foreach (var child in children)
                WriteNode(s, child);
        }
        else if (node.Content is byte[] data)
        {
            WriteBinary(s, data);
        }
        else if (node.Content is string text)
        {
            WriteString(s, text);
        }
    }

    private static void WriteListSize(Stream s, int size)
    {
        if (size == 0)
        {
            s.WriteByte(WATags.ListEmpty);
        }
        else if (size <= 255)
        {
            s.WriteByte(WATags.List8);
            s.WriteByte((byte)size);
        }
        else
        {
            s.WriteByte(WATags.List16);
            s.WriteByte((byte)(size >> 8));
            s.WriteByte((byte)(size & 0xFF));
        }
    }

    private static void WriteBinary(Stream s, byte[] data)
    {
        if (data.Length <= 255)
        {
            s.WriteByte(WATags.Binary8);
            s.WriteByte((byte)data.Length);
        }
        else if (data.Length <= 0xFFFFF)
        {
            s.WriteByte(WATags.Binary20);
            s.WriteByte((byte)((data.Length >> 16) & 0x0F));
            s.WriteByte((byte)((data.Length >> 8) & 0xFF));
            s.WriteByte((byte)(data.Length & 0xFF));
        }
        else
        {
            s.WriteByte(WATags.Binary32);
            s.WriteByte((byte)((data.Length >> 24) & 0xFF));
            s.WriteByte((byte)((data.Length >> 16) & 0xFF));
            s.WriteByte((byte)((data.Length >> 8) & 0xFF));
            s.WriteByte((byte)(data.Length & 0xFF));
        }
        s.Write(data);
    }

    private static void WriteString(Stream s, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            s.WriteByte(WATags.ListEmpty);
            return;
        }

        // Try dictionary lookup first
        if (WATags.TryGetToken(value, out var dictByte, out var idxByte))
        {
            s.WriteByte(dictByte);
            s.WriteByte(idxByte);
            return;
        }

        // Check if it's a JID (user@server)
        var atIdx = value.IndexOf('@');
        if (atIdx > 0)
        {
            var user = value[..atIdx];
            var server = value[(atIdx + 1)..];
            s.WriteByte(WATags.JidPair);
            WriteString(s, user);
            WriteString(s, server);
            return;
        }

        // Raw string
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length <= 255)
        {
            s.WriteByte(WATags.Binary8);
            s.WriteByte((byte)bytes.Length);
        }
        else if (bytes.Length <= 0xFFFFF)
        {
            s.WriteByte(WATags.Binary20);
            s.WriteByte((byte)((bytes.Length >> 16) & 0x0F));
            s.WriteByte((byte)((bytes.Length >> 8) & 0xFF));
            s.WriteByte((byte)(bytes.Length & 0xFF));
        }
        else
        {
            s.WriteByte(WATags.Binary32);
            s.WriteByte((byte)((bytes.Length >> 24) & 0xFF));
            s.WriteByte((byte)((bytes.Length >> 16) & 0xFF));
            s.WriteByte((byte)((bytes.Length >> 8) & 0xFF));
            s.WriteByte((byte)(bytes.Length & 0xFF));
        }
        s.Write(bytes);
    }
}
