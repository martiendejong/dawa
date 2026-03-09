# Dawa 🦁

> **C# port of Baileys** — a WhatsApp Web client library for .NET

Use WhatsApp from any .NET application (ASP.NET Core, IIS, console, worker service) without running a Node.js server.

[![NuGet](https://img.shields.io/nuget/v/Dawa.WhatsApp)](https://www.nuget.org/packages/Dawa.WhatsApp)
[![Build](https://github.com/martiendejong/dawa/actions/workflows/ci.yml/badge.svg)](https://github.com/martiendejong/dawa/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## Why Dawa?

The [Baileys](https://github.com/WhiskeySockets/Baileys) library is great but requires Node.js. If you have an IIS / ASP.NET Core app, running a sidecar Node process adds complexity and points of failure. Dawa brings the WhatsApp Web protocol natively to .NET.

**Name:** *Dawa* is Swahili for "medicine" — it fixes the Node.js dependency problem.

---

## Features

- **No Node.js** — pure .NET 8 implementation
- **QR code pairing** — first-time auth via QR scan, just like Baileys
- **Session persistence** — saves credentials to disk, restores automatically
- **Send text messages** — to any phone number or JID
- **Receive messages** — event-driven, non-blocking
- **ASP.NET Core DI** — `services.AddWhatsApp()`
- **Auto-reconnect** — configurable reconnect on connection loss

---

## Architecture

```
┌─────────────────────────────────────────────┐
│               WhatsAppClient                 │  ← Public API
├─────────────────────────────────────────────┤
│           NoiseProcessor                    │  ← Noise XX handshake
│    Noise_XX_25519_AESGCM_SHA256             │
├─────────────────────────────────────────────┤
│     BinaryNode Encoder/Decoder              │  ← WA binary protocol
├─────────────────────────────────────────────┤
│          FrameSocket                        │  ← WebSocket + framing
│   wss://web.whatsapp.com/ws/chat            │
└─────────────────────────────────────────────┘
```

---

## Installation

```bash
dotnet add package Dawa.WhatsApp
```

---

## Quick Start

### Console app

```csharp
using Dawa;

await using var client = WhatsAppClient.Create("./wa-session");

// First run: fires QR code for scanning
client.QRCodeReceived += (_, qr) =>
{
    // Print to console, show in browser, generate image — your choice
    Console.WriteLine("Scan: " + qr);
    // Or use QRCoder to render in the terminal:
    // var qrCode = new AsciiQRCode(new QRCodeGenerator().CreateQrCode(qr, ECCLevel.L));
    // Console.WriteLine(qrCode.GetGraphic(1));
};

client.MessageReceived += (_, msg) =>
    Console.WriteLine($"{msg.From}: {msg.Text}");

await client.ConnectAsync();
await client.WaitUntilConnectedAsync();

await client.SendMessageAsync("+31612345678", "Hello from Dawa!");
```

### ASP.NET Core / IIS

**Program.cs:**
```csharp
builder.Services.AddWhatsApp(options =>
{
    options.SessionDirectory = "/var/whatsapp-session";
    options.AutoReconnect = true;
});
```

**WhatsAppController.cs:**
```csharp
[ApiController]
[Route("api/whatsapp")]
public class WhatsAppController : ControllerBase
{
    private readonly WhatsAppClient _wa;

    public WhatsAppController(WhatsAppClient wa) => _wa = wa;

    [HttpPost("send")]
    public async Task<IActionResult> Send([FromBody] SendRequest req)
    {
        await _wa.SendMessageAsync(req.To, req.Text);
        return Ok();
    }

    [HttpGet("status")]
    public IActionResult Status() => Ok(_wa.State.ToString());
}
```

---

## QR Code

The `QRCodeReceived` event fires a raw QR string. Render it however you like:

```csharp
// In console: use QRCoder ASCII
client.QRCodeReceived += (_, qr) => {
    var code = new AsciiQRCode(new QRCodeGenerator().CreateQrCode(qr, ECCLevel.L));
    Console.WriteLine(code.GetGraphic(1));
};

// In web: return QR as PNG
client.QRCodeReceived += async (_, qr) => {
    using var qrGen = new QRCodeGenerator();
    var data = qrGen.CreateQrCode(qr, ECCLevel.L);
    var png = new PngByteQRCode(data);
    await File.WriteAllBytesAsync("qr.png", png.GetGraphic(10));
};
```

---

## Protocol Implementation

Dawa implements the **WhatsApp Web multi-device protocol**:

| Layer | Implementation |
|-------|---------------|
| Transport | `System.Net.WebSockets` |
| Framing | 3-byte big-endian length prefix |
| Encryption | Noise_XX_25519_AESGCM_SHA256 |
| Key exchange | Curve25519 (BouncyCastle) |
| AEAD | AES-256-GCM (.NET built-in) |
| KDF | HKDF-SHA256 (.NET built-in) |
| Message format | Binary nodes (custom dict compression) |
| Serialization | Protobuf (Google.Protobuf) |
| E2E encryption | Signal Double Ratchet |

---

## Limitations (v0.1)

- Text messages only (no media yet)
- No group management
- No presence / typing indicators
- Signal pre-key upload not yet automated (works after initial pairing)

These are all on the roadmap. PRs welcome!

---

## Compared to Baileys

| Feature | Baileys (JS) | Dawa (C#) |
|---------|-------------|-----------|
| Runtime | Node.js | .NET 8 |
| IIS compatible | No | Yes |
| Text messages | Yes | Yes |
| Media | Yes | Planned |
| Groups | Yes | Planned |
| Session persistence | Yes | Yes |
| Auto-reconnect | Yes | Yes |

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Commit your changes
4. Push and open a PR

---

## Legal

This library uses the WhatsApp Web protocol which is reverse-engineered. Use responsibly and in accordance with [WhatsApp's Terms of Service](https://www.whatsapp.com/legal/terms-of-service). This project is not affiliated with or endorsed by Meta/WhatsApp.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
