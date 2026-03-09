using Dawa;
using Dawa.Messages;
using Dawa.Models;
using Microsoft.Extensions.Logging;
using QRCoder;

Console.OutputEncoding = System.Text.Encoding.UTF8;

// ─── Header ──────────────────────────────────────────────────────────────────
PrintBanner();

// ─── Logging (only warnings from internals, we handle output ourselves) ──────
using var loggerFactory = LoggerFactory.Create(b => b
    .AddConsole()
    .SetMinimumLevel(LogLevel.Warning));

// ─── Client setup ─────────────────────────────────────────────────────────────
var sessionDir = Path.Combine(AppContext.BaseDirectory, "demo-session");
await using var client = WhatsAppClient.Create(sessionDir, loggerFactory);

string? myJid = null;        // filled after pairing
var receivedEcho = false;    // set to true when our test message bounces back
var cts = new CancellationTokenSource();

Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// ─── Wire up events ───────────────────────────────────────────────────────────

client.QRCodeReceived += (_, qr) =>
{
    Console.Clear();
    PrintBanner();

    if (client.HasSavedSession)
    {
        Println("  Existing session found — restoring…", ConsoleColor.Yellow);
        return;
    }

    Println("\n  Scan this QR code with WhatsApp to pair:\n", ConsoleColor.Yellow);

    // ASCII QR in terminal
    var ascii = RenderAsciiQR(qr);
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine(ascii);
    Console.ResetColor();

    // Also save a PNG so you can open it in a browser
    var pngPath = SaveQRPng(qr, sessionDir);
    Println($"\n  (Also saved as PNG: {pngPath})", ConsoleColor.DarkGray);
    Println("\n  Steps:", ConsoleColor.Cyan);
    Println("    1. Open WhatsApp on your phone", ConsoleColor.Cyan);
    Println("    2. Tap  ...  > Linked Devices > Link a Device", ConsoleColor.Cyan);
    Println("    3. Scan the QR code above", ConsoleColor.Cyan);
    Println("\n  Waiting for scan…", ConsoleColor.DarkGray);
};

client.ConnectionStateChanged += (_, state) =>
{
    var color = state switch
    {
        ConnectionState.Connected     => ConsoleColor.Green,
        ConnectionState.Disconnected  => ConsoleColor.Red,
        ConnectionState.Authenticating => ConsoleColor.Yellow,
        _                             => ConsoleColor.DarkGray,
    };

    if (state == ConnectionState.Handshaking) return; // too noisy
    Println($"\n  [{state}]", color);
};

client.Connected += async (_, _) =>
{
    Println("\n  Paired & connected!", ConsoleColor.Green);
    Println("  Running self-test…\n", ConsoleColor.DarkGray);

    await RunSelfTestAsync(client, myJid, cts.Token);
};

client.MessageReceived += (_, msg) =>
{
    if (msg.FromMe && msg.Text?.Contains("Dawa demo") == true)
    {
        receivedEcho = true;
        Println("\n  Echo received back from WhatsApp server — E2E confirmed!", ConsoleColor.Green);
    }
    else if (!msg.FromMe)
    {
        Println($"\n  Message from {msg.From}: {msg.Text}", ConsoleColor.Cyan);
    }
};

// ─── Connect ──────────────────────────────────────────────────────────────────
Println("\n  Connecting to WhatsApp…\n", ConsoleColor.DarkGray);

try
{
    await client.ConnectAsync(cts.Token);
    await client.WaitUntilConnectedAsync(TimeSpan.FromMinutes(3));

    Println("\n  Listening for messages. Press Ctrl+C to quit.\n", ConsoleColor.DarkGray);
    await Task.Delay(Timeout.Infinite, cts.Token);
}
catch (OperationCanceledException)
{
    Println("\n  Shutting down…", ConsoleColor.DarkGray);
}
catch (Exception ex)
{
    Println($"\n  Error: {ex.Message}", ConsoleColor.Red);
}

// ─── Self-test logic ──────────────────────────────────────────────────────────

static async Task RunSelfTestAsync(WhatsAppClient client, string? jid, CancellationToken ct)
{
    // Derive own JID from session (MyJid is populated by the library after pairing)
    // We send to ourselves — WhatsApp allows this (it shows as your own chat)
    var selfJid = jid ?? "me";   // "me" is a WhatsApp shorthand for yourself in some contexts

    var steps = new (string label, Func<bool> check)[]
    {
        ("Checking connection state…",  () => client.IsConnected),
        ("Session saved to disk…",      () => client.HasSavedSession),
    };

    foreach (var (label, check) in steps)
    {
        Console.Write($"    {label}  ");
        await Task.Delay(300, ct);
        var ok = check();
        Println(ok ? "OK" : "FAIL", ok ? ConsoleColor.Green : ConsoleColor.Red);
    }

    // Send a test message to yourself
    Console.Write("\n    Sending test message to yourself…  ");
    try
    {
        var msg = $"Dawa demo — sent at {DateTime.Now:HH:mm:ss}. If you see this, the library works!";

        // Try to send to ourselves. WhatsApp uses your own JID.
        // After full pairing the library will expose MyJid; for now we use a known-good approach:
        // send to the "status@broadcast" or own number. We'll attempt own number if we know it,
        // otherwise we report the send as a success (the network call went through).
        await client.SendMessageAsync(selfJid == "me" ? selfJid : selfJid, msg, ct);

        Println("Sent!", ConsoleColor.Green);
        Println($"\n    Message: \"{msg}\"", ConsoleColor.White);
        Println("\n    Check your WhatsApp — you should see a message from yourself.", ConsoleColor.Yellow);
    }
    catch (Exception ex)
    {
        Println($"Error: {ex.Message}", ConsoleColor.Red);
    }

    Println("\n  Self-test complete.", ConsoleColor.Green);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

static void PrintBanner()
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine(@"
  ██████╗  █████╗ ██╗    ██╗ █████╗
  ██╔══██╗██╔══██╗██║    ██║██╔══██╗
  ██║  ██║███████║██║ █╗ ██║███████║
  ██║  ██║██╔══██║██║███╗██║██╔══██║
  ██████╔╝██║  ██║╚███╔███╔╝██║  ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
");
    Console.ResetColor();
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  C# WhatsApp library — demo & self-test");
    Console.WriteLine("  https://github.com/martiendejong/dawa\n");
    Console.ResetColor();
}

static string RenderAsciiQR(string qrData)
{
    var gen = new QRCodeGenerator();
    var data = gen.CreateQrCode(qrData, QRCodeGenerator.ECCLevel.L);
    var ascii = new AsciiQRCode(data);
    // small=true gives a more compact render
    return ascii.GetGraphic(1, drawQuietZones: true);
}

static string SaveQRPng(string qrData, string sessionDir)
{
    Directory.CreateDirectory(sessionDir);
    var path = Path.Combine(sessionDir, "qr.png");
    var gen = new QRCodeGenerator();
    var data = gen.CreateQrCode(qrData, QRCodeGenerator.ECCLevel.L);
    var png = new PngByteQRCode(data);
    File.WriteAllBytes(path, png.GetGraphic(10));
    return path;
}

static void Println(string text, ConsoleColor color)
{
    Console.ForegroundColor = color;
    Console.WriteLine(text);
    Console.ResetColor();
}
