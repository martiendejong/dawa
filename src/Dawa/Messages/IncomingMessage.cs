namespace Dawa.Messages;

/// <summary>
/// Represents a received WhatsApp message.
/// </summary>
public sealed class IncomingMessage
{
    /// <summary>Unique message ID assigned by WhatsApp.</summary>
    public string Id { get; init; } = "";

    /// <summary>Sender JID (e.g. "31612345678@s.whatsapp.net").</summary>
    public string From { get; init; } = "";

    /// <summary>The conversation/chat JID.</summary>
    public string RemoteJid { get; init; } = "";

    /// <summary>For group messages: the participant who sent the message.</summary>
    public string? Participant { get; init; }

    /// <summary>Text content of the message, if it's a text message.</summary>
    public string? Text { get; init; }

    /// <summary>True if this message was sent by ourselves.</summary>
    public bool FromMe { get; init; }

    /// <summary>Unix timestamp (seconds) when the message was sent.</summary>
    public long Timestamp { get; init; }

    /// <summary>UTC timestamp of the message.</summary>
    public DateTimeOffset SentAt => DateTimeOffset.FromUnixTimeSeconds(Timestamp);

    public override string ToString() =>
        $"[{SentAt:HH:mm:ss}] {(FromMe ? "ME" : From)}: {Text ?? "<no text>"}";
}
