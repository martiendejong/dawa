namespace Dawa;

/// <summary>Configuration options for the WhatsApp client.</summary>
public sealed class WhatsAppClientOptions
{
    /// <summary>Directory where session credentials are stored. Default: ./whatsapp-session</summary>
    public string SessionDirectory { get; set; } = "./whatsapp-session";

    /// <summary>Browser name shown in WhatsApp's "Linked Devices" list.</summary>
    public string BrowserName { get; set; } = "Dawa";

    /// <summary>Browser version reported to WhatsApp.</summary>
    public string BrowserVersion { get; set; } = "0.1.0";

    /// <summary>
    /// How long to wait for a QR code scan before timing out.
    /// Default: 2 minutes.
    /// </summary>
    public TimeSpan QRCodeTimeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// How long to wait for server responses during connection.
    /// Default: 30 seconds.
    /// </summary>
    public TimeSpan ConnectionTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Whether to auto-reconnect on connection loss.
    /// Default: true.
    /// </summary>
    public bool AutoReconnect { get; set; } = true;

    /// <summary>
    /// Delay between reconnect attempts.
    /// Default: 5 seconds.
    /// </summary>
    public TimeSpan ReconnectDelay { get; set; } = TimeSpan.FromSeconds(5);
}
