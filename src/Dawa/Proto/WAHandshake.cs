namespace Dawa.Proto;

// ─────────────────────────────────────────────────────────────
// Hand-crafted proto3 serialization for the WhatsApp Noise handshake.
// Uses our minimal ProtoEncoder/ProtoReader instead of IBufferMessage.
// ─────────────────────────────────────────────────────────────

public sealed class ClientHello
{
    public byte[] Ephemeral { get; set; } = [];
    public byte[] Static    { get; set; } = [];
    public byte[] Payload   { get; set; } = [];

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteBytes(buf, 1, Ephemeral);
        ProtoEncoder.WriteBytes(buf, 2, Static);
        ProtoEncoder.WriteBytes(buf, 3, Payload);
        return [.. buf];
    }
}

public sealed class ServerHello
{
    public byte[] Ephemeral { get; set; } = [];
    public byte[] Static    { get; set; } = [];
    public byte[] Payload   { get; set; } = [];

    public static ServerHello ParseFrom(byte[] data)
    {
        var msg = new ServerHello();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Ephemeral = r.ReadBytes(); break;
                case 2: msg.Static    = r.ReadBytes(); break;
                case 3: msg.Payload   = r.ReadBytes(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}

public sealed class ClientFinish
{
    public byte[] Static  { get; set; } = [];
    public byte[] Payload { get; set; } = [];

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        ProtoEncoder.WriteBytes(buf, 1, Static);
        ProtoEncoder.WriteBytes(buf, 2, Payload);
        return [.. buf];
    }
}

public sealed class HandshakeMessage
{
    public ClientHello?  ClientHello  { get; set; }
    public ServerHello?  ServerHello  { get; set; }
    public ClientFinish? ClientFinish { get; set; }

    public byte[] ToByteArray()
    {
        var buf = new List<byte>();
        if (ClientHello  != null) ProtoEncoder.WriteMessage(buf, 2, ClientHello.ToByteArray());
        if (ServerHello  != null) { /* server-only */ }
        if (ClientFinish != null) ProtoEncoder.WriteMessage(buf, 4, ClientFinish.ToByteArray()); // field 4, not 5!
        return [.. buf];
    }

    public static HandshakeMessage ParseFrom(byte[] data)
    {
        var msg = new HandshakeMessage();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 2: msg.ClientHello  = ParseClientHello(r.ReadBytes());  break;
                case 3: msg.ServerHello  = ServerHello.ParseFrom(r.ReadBytes()); break;
                case 4: msg.ClientFinish = ParseClientFinish(r.ReadBytes()); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    private static ClientHello ParseClientHello(byte[] data)
    {
        var msg = new ClientHello();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Ephemeral = r.ReadBytes(); break;
                case 2: msg.Static    = r.ReadBytes(); break;
                case 3: msg.Payload   = r.ReadBytes(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }

    private static ClientFinish ParseClientFinish(byte[] data)
    {
        var msg = new ClientFinish();
        var r = ProtoEncoder.CreateReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            switch (field)
            {
                case 1: msg.Static  = r.ReadBytes(); break;
                case 2: msg.Payload = r.ReadBytes(); break;
                default: r.Skip(wire); break;
            }
        }
        return msg;
    }
}
