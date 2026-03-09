namespace Dawa.Proto;

// ─────────────────────────────────────────────────────────────
// Hand-crafted proto3 for WhatsApp message types.
// ─────────────────────────────────────────────────────────────

public sealed class ClientPayload
{
    public ulong  Username      { get; set; }
    public bool   Passive       { get; set; }
    public UserAgent? UserAgent { get; set; }
    public WebInfo?   WebInfo   { get; set; }
    public string ConnectReason { get; set; } = "USER_ACTIVATED";
    public int    ConnectType   { get; set; } = 1;

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteUInt64(buf, 1, Username);
        ProtoEncoder.WriteBool(buf, 3, Passive);
        if (UserAgent != null) ProtoEncoder.WriteMessage(buf, 5, UserAgent.ToByteArray());
        if (WebInfo   != null) ProtoEncoder.WriteMessage(buf, 6, WebInfo.ToByteArray());
        ProtoEncoder.WriteString(buf, 12, ConnectReason);
        ProtoEncoder.WriteInt32(buf, 13, ConnectType);
        return [.. buf];
    }
}

public sealed class UserAgent
{
    public int        Platform                  { get; set; } = 14;
    public AppVersion? AppVersion               { get; set; }
    public string Mcc                           { get; set; } = "000";
    public string Mnc                           { get; set; } = "000";
    public string OsVersion                     { get; set; } = "0.1";
    public string Manufacturer                  { get; set; } = "";
    public string Device                        { get; set; } = "Desktop";
    public string OsBuildNumber                 { get; set; } = "0.1";
    public string LocaleLanguageIso6391         { get; set; } = "en";
    public string LocaleCountryIso31661Alpha2   { get; set; } = "en";

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteInt32(buf, 1, Platform);
        if (AppVersion != null) ProtoEncoder.WriteMessage(buf, 2, AppVersion.ToByteArray());
        ProtoEncoder.WriteString(buf, 3, Mcc);
        ProtoEncoder.WriteString(buf, 4, Mnc);
        ProtoEncoder.WriteString(buf, 5, OsVersion);
        ProtoEncoder.WriteString(buf, 6, Manufacturer);
        ProtoEncoder.WriteString(buf, 7, Device);
        ProtoEncoder.WriteString(buf, 8, OsBuildNumber);
        ProtoEncoder.WriteString(buf, 9, LocaleLanguageIso6391);
        ProtoEncoder.WriteString(buf, 10, LocaleCountryIso31661Alpha2);
        return [.. buf];
    }
}

public sealed class AppVersion
{
    public uint Primary   { get; set; } = 2;
    public uint Secondary { get; set; } = 3000;
    public uint Tertiary  { get; set; } = 1017531287;

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteUInt32(buf, 1, Primary);
        ProtoEncoder.WriteUInt32(buf, 2, Secondary);
        ProtoEncoder.WriteUInt32(buf, 3, Tertiary);
        return [.. buf];
    }
}

public sealed class WebInfo
{
    public string RefToken      { get; set; } = "";
    public int    WebSubPlatform { get; set; } = 0;

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, RefToken);
        ProtoEncoder.WriteInt32(buf, 2, WebSubPlatform);
        return [.. buf];
    }
}

/// <summary>WhatsApp message content proto.</summary>
public sealed class WAMessage
{
    public string? Conversation { get; set; }
    public ExtendedTextMessage? ExtendedTextMessage { get; set; }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Conversation);
        if (ExtendedTextMessage != null)
            ProtoEncoder.WriteMessage(buf, 2, ExtendedTextMessage.ToByteArray());
        return [.. buf];
    }

    public static WAMessage ParseFrom(byte[] data)
    {
        var msg = new WAMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1:
                    msg.Conversation = r.ReadString();
                    break;
                case 2:
                    msg.ExtendedTextMessage = ExtendedTextMessage.ParseFrom(r.ReadBytes());
                    break;
                default:
                    r.Skip(wire);
                    break;
            }
        }
        return msg;
    }
}

public sealed class ExtendedTextMessage
{
    public string Text { get; set; } = "";

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteString(buf, 1, Text);
        return [.. buf];
    }

    public static ExtendedTextMessage ParseFrom(byte[] data)
    {
        var msg = new ExtendedTextMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (field == 1) msg.Text = r.ReadString();
            else r.Skip(wire);
        }
        return msg;
    }
}
