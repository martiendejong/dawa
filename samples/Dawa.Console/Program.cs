using Dawa;
using Dawa.Models;
using Microsoft.Extensions.Logging;
using QRCoder;

// ─── Setup logging ───────────────────────────────────────────────────────────
using var loggerFactory = LoggerFactory.Create(b => b
    .AddConsole()
    .SetMinimumLevel(LogLevel.Information));

Console.WriteLine("Dawa WhatsApp Client — Sample App");
Console.WriteLine("===================================\n");

// ─── Parse args ──────────────────────────────────────────────────────────────
var command = args.Length > 0 ? args[0].ToLower() : "connect";
var sessionDir = "./wa-session";

// ─── Create client ───────────────────────────────────────────────────────────
await using var client = WhatsAppClient.Create(sessionDir, loggerFactory);

if (command == "logout")
{
    client.Logout();
    Console.WriteLine("Session deleted. Run without args to re-pair.");
    return;
}

if (command == "send" && args.Length >= 3)
{
    var to = args[1];
    var message = string.Join(' ', args[2..]);
    await SendMessageFlow(client, to, message);
    return;
}

// Default: interactive connect
await InteractiveFlow(client);

// ─────────────────────────────────────────────────────────────────────────────

async Task InteractiveFlow(WhatsAppClient wa)
{
    var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    wa.QRCodeReceived += (_, qr) =>
    {
        Console.WriteLine("\nScan this QR code with WhatsApp:\n");
        PrintQRCode(qr);
        Console.WriteLine("\nWaiting for scan…");
    };

    wa.ConnectionStateChanged += (_, state) =>
    {
        var icon = state switch
        {
            ConnectionState.Connected => "[CONNECTED]",
            ConnectionState.Disconnected => "[DISCONNECTED]",
            ConnectionState.Authenticating => "[AUTHENTICATING]",
            ConnectionState.Handshaking => "[HANDSHAKING]",
            _ => $"[{state}]"
        };
        Console.WriteLine($"\n{icon}");
    };

    wa.MessageReceived += (_, msg) =>
    {
        Console.ForegroundColor = msg.FromMe ? ConsoleColor.Cyan : ConsoleColor.Green;
        Console.WriteLine($"\n[{msg.SentAt:HH:mm:ss}] {msg.From}: {msg.Text}");
        Console.ResetColor();
    };

    wa.Disconnected += (_, _) => Console.WriteLine("\nDisconnected.");

    Console.WriteLine("Connecting to WhatsApp…");

    try
    {
        await wa.ConnectAsync(cts.Token);
        Console.WriteLine("Waiting for authentication…");
        await wa.WaitUntilConnectedAsync(TimeSpan.FromMinutes(2));
        Console.WriteLine("\nReady! Type a message to send (format: <number> <message>) or Ctrl+C to quit.\n");

        while (!cts.Token.IsCancellationRequested)
        {
            var line = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(line)) continue;

            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                Console.WriteLine("Format: <phone_number> <message>");
                continue;
            }

            try
            {
                await wa.SendMessageAsync(parts[0], parts[1], cts.Token);
                Console.WriteLine("Sent.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
    catch (OperationCanceledException)
    {
        Console.WriteLine("Disconnecting…");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error: {ex.Message}");
    }
}

async Task SendMessageFlow(WhatsAppClient wa, string to, string message)
{
    if (!wa.HasSavedSession)
    {
        Console.WriteLine("No saved session. Run without args first to scan QR code.");
        return;
    }

    Console.WriteLine($"Sending to {to}: {message}");

    wa.Connected += async (_, _) =>
    {
        await wa.SendMessageAsync(to, message);
        Console.WriteLine("Message sent.");
        Environment.Exit(0);
    };

    await wa.ConnectAsync();
    await wa.WaitUntilConnectedAsync(TimeSpan.FromSeconds(30));
}

void PrintQRCode(string qrData)
{
    var qrGenerator = new QRCodeGenerator();
    var qrCodeData = qrGenerator.CreateQrCode(qrData, QRCodeGenerator.ECCLevel.L);
    var qrCode = new AsciiQRCode(qrCodeData);
    var art = qrCode.GetGraphic(1);
    Console.WriteLine(art);
}
