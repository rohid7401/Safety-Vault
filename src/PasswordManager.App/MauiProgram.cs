using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
using PasswordManager.App.Platform;
using PasswordManager.Infrastructure;
using PasswordManager.UI.Abstractions;
using PasswordManager.UI.Localization;
using PasswordManager.UI.Services;

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

        // Shared UI services (from PasswordManager.UI)
        builder.Services.AddSingleton<AppState>();
        builder.Services.AddSingleton<VaultAutoLock>();
        builder.Services.AddSingleton<ToastService>();
        builder.Services.AddSingleton<GeneratorPreferences>();
        builder.Services.AddHttpClient<KeyServerService>();

        // Localization
        builder.Services.AddSingleton<ILanguageStore, MauiLanguageStore>();
        builder.Services.AddSingleton<Loc>();
        builder.Services.AddSingleton<ITutorialStore, MauiTutorialStore>();

        // Platform implementations of the UI abstractions
        builder.Services.AddSingleton<IClipboardService, MauiClipboardService>();
        builder.Services.AddSingleton<IFilePickerService, MauiFilePickerService>();
        builder.Services.AddSingleton<IPlatformInfo, MauiPlatformInfo>();
        builder.Services.AddSingleton<SecureClipboardService>();

#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}
