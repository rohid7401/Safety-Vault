using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
using PasswordManager.App.Services;
using PasswordManager.Infrastructure;

namespace PasswordManager.App;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .UseMauiCommunityToolkit()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
            });

        builder.Services.AddMauiBlazorWebView();

        // Resolve a writable app data root for accounts + vaults
        var appData = Path.Combine(FileSystem.AppDataDirectory, "SecureVault");
        Directory.CreateDirectory(appData);

        builder.Services.AddPasswordManager(opts =>
        {
            opts.AppDataPath = appData;
        });

        builder.Services.AddSingleton<AppState>();
        builder.Services.AddSingleton<FileSystemPicker>();
        builder.Services.AddSingleton<ToastService>();
        builder.Services.AddSingleton<GeneratorPreferences>();
        builder.Services.AddHttpClient<KeyServerService>();

#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}
