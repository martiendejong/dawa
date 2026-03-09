using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Dawa.Extensions;

/// <summary>
/// Extension methods for registering Dawa with Microsoft DI (ASP.NET Core, etc.).
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="WhatsAppClient"/> as a singleton service.
    ///
    /// Usage in Program.cs:
    /// <code>
    /// builder.Services.AddWhatsApp(options =>
    /// {
    ///     options.SessionDirectory = "./whatsapp-session";
    ///     options.AutoReconnect = true;
    /// });
    /// </code>
    ///
    /// Then inject IWhatsAppService or WhatsAppClient into your controllers.
    /// </summary>
    public static IServiceCollection AddWhatsApp(
        this IServiceCollection services,
        Action<WhatsAppClientOptions>? configure = null)
    {
        var options = new WhatsAppClientOptions();
        configure?.Invoke(options);

        services.AddSingleton(options);
        services.AddSingleton(sp =>
        {
            var logger = sp.GetService<ILoggerFactory>();
            return logger != null
                ? WhatsAppClient.Create(options.SessionDirectory, logger)
                : WhatsAppClient.Create(options.SessionDirectory);
        });

        return services;
    }
}
