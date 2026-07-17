namespace Dawa.Messages;

/// <summary>Message type classification.</summary>
public enum MessageType
{
    Unknown,
    Text,
    Image,
    Video,
    Audio,
    Document,
    Sticker,
    Reaction,
    Location,
    Contact,
    Protocol,   // ProtocolMessage (history sync, key distribution, etc.)
}

/// <summary>Delivery/read status of an outgoing message.</summary>
public enum MessageStatus
{
    Sent,       // Sent to WhatsApp servers
    Delivered,  // Delivered to recipient device
    Read,       // Recipient read the message
    Played,     // Recipient played the voice note
}

/// <summary>
/// Represents a received WhatsApp message.
/// </summary>
public sealed class IncomingMessage
{
    /// <summary>Unique message ID assigned by WhatsApp.</summary>
    public string Id { get; init; } = "";

    /// <summary>Sender JID (e.g. "31612345678@s.whatsapp.net" or LID).</summary>
    public string From { get; init; } = "";

    /// <summary>The conversation/chat JID.</summary>
    public string RemoteJid { get; init; } = "";

    /// <summary>For group messages: the participant who sent the message.</summary>
    public string? Participant { get; init; }

    /// <summary>Classified message type.</summary>
    public MessageType Type { get; init; } = MessageType.Unknown;

    /// <summary>Text content (for Text messages, or caption for media).</summary>
    public string? Text { get; init; }

    /// <summary>True if this message was sent by ourselves.</summary>
    public bool FromMe { get; init; }

    /// <summary>Unix timestamp (seconds) when the message was sent.</summary>
    public long Timestamp { get; init; }

    /// <summary>The push name (display name) of the sender, if provided.</summary>
    public string? PushName { get; init; }

    /// <summary>True if this message has been revoked (deleted for everyone).</summary>
    public bool IsRevoked { get; init; }

    // ── Media fields ──────────────────────────────────────────────────────────

    /// <summary>Direct CDN URL to download the encrypted media.</summary>
    public string? MediaUrl { get; init; }

    /// <summary>MIME type (e.g. "image/jpeg", "audio/ogg; codecs=opus").</summary>
    public string? MimeType { get; init; }

    /// <summary>File name (primarily for documents).</summary>
    public string? FileName { get; init; }

    /// <summary>File size in bytes.</summary>
    public long? FileSize { get; init; }

    /// <summary>Duration in seconds (audio/video).</summary>
    public uint? Duration { get; init; }

    /// <summary>Width in pixels (image/video/sticker).</summary>
    public uint? Width { get; init; }

    /// <summary>Height in pixels (image/video/sticker).</summary>
    public uint? Height { get; init; }

    /// <summary>Base64-encoded AES key to decrypt the media download.</summary>
    public string? MediaKey { get; init; }

    /// <summary>Base64-encoded SHA256 of the encrypted media blob.</summary>
    public string? MediaSha256Enc { get; init; }

    // ── Reaction fields ───────────────────────────────────────────────────────

    /// <summary>Reaction emoji (e.g. "👍"). Empty string = reaction removed.</summary>
    public string? ReactionEmoji { get; init; }

    /// <summary>ID of the message being reacted to.</summary>
    public string? ReactionTargetId { get; init; }

    // ── Quoted/reply context ──────────────────────────────────────────────────

    /// <summary>ID of the message this is a reply to.</summary>
    public string? QuotedMessageId { get; init; }

    /// <summary>JID of the sender of the quoted message.</summary>
    public string? QuotedFrom { get; init; }

    /// <summary>Text preview of the quoted message.</summary>
    public string? QuotedText { get; init; }

    /// <summary>Type of the quoted message.</summary>
    public MessageType QuotedType { get; init; } = MessageType.Unknown;

    // ── UTC helper ────────────────────────────────────────────────────────────

    public DateTimeOffset SentAt => DateTimeOffset.FromUnixTimeSeconds(Timestamp);

    public override string ToString() =>
        $"[{SentAt:HH:mm:ss}] {(FromMe ? "ME" : From)} [{Type}]: {Text ?? MediaUrl ?? ReactionEmoji ?? "<no content>"}";
}
