namespace Dawa.Models;

/// <summary>
/// WhatsApp JID (Jabber ID) — uniquely identifies a user, group, or server.
/// </summary>
public readonly struct JID : IEquatable<JID>
{
    public string User { get; }
    public string Server { get; }
    public string? Device { get; }

    public static readonly string ServerUser = "s.whatsapp.net";
    public static readonly string ServerGroup = "g.us";
    public static readonly string ServerBroadcast = "broadcast";

    public JID(string user, string server, string? device = null)
    {
        User = user;
        Server = server;
        Device = device;
    }

    /// <summary>Creates a user JID from a phone number (digits only, include country code).</summary>
    public static JID FromPhone(string phone)
    {
        var digits = new string(phone.Where(char.IsDigit).ToArray());
        if (digits.StartsWith("00")) digits = digits[2..];
        return new JID(digits, ServerUser);
    }

    /// <summary>Parses a JID string like "1234567890@s.whatsapp.net".</summary>
    public static JID Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) throw new ArgumentException("Empty JID.");
        var colonIdx = raw.IndexOf(':');
        var atIdx = raw.IndexOf('@');
        if (atIdx < 0) return new JID(raw, ServerUser);
        var user = atIdx > 0 ? raw[..atIdx] : "";
        var server = raw[(atIdx + 1)..];
        if (colonIdx > 0 && colonIdx < atIdx)
        {
            user = raw[..colonIdx];
            var device = raw[(colonIdx + 1)..atIdx];
            return new JID(user, server, device);
        }
        return new JID(user, server);
    }

    public bool IsGroup => Server == ServerGroup;
    public bool IsUser => Server == ServerUser;

    public override string ToString() =>
        Device != null ? $"{User}:{Device}@{Server}" : $"{User}@{Server}";

    public bool Equals(JID other) => User == other.User && Server == other.Server && Device == other.Device;
    public override bool Equals(object? obj) => obj is JID j && Equals(j);
    public override int GetHashCode() => HashCode.Combine(User, Server, Device);
    public static bool operator ==(JID a, JID b) => a.Equals(b);
    public static bool operator !=(JID a, JID b) => !a.Equals(b);
}
