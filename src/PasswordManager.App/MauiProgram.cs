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
        // Both of these read their timing from the account's settings, and read it at the moment
        // they act: they are built before any vault is open, so capturing a value here would pin
        // whatever it was before the user had signed in.
        builder.Services.AddSingleton(sp => new VaultAutoLock(
            () => TimeSpan.FromSeconds(
                sp.GetRequiredService<AppSettings>().Get(AppSettingsCatalog.AutoLockGraceSeconds)),
            VaultAutoLock.DefaultExcursionGracePeriod,
            AutoLockClock.Now));
        builder.Services.AddSingleton<ShellBackNavigation>();
        builder.Services.AddSingleton<ToastService>();
        builder.Services.AddSingleton<GeneratorPreferences>();
        builder.Services.AddSingleton<AppSettings>();
        // Still registered because ViewPreferences reads it once, to carry over a choice made
        // before these moved into the vault. Nothing writes to it any more.
        builder.Services.AddSingleton<IViewPreferenceStore, MauiViewPreferenceStore>();
        builder.Services.AddSingleton<ViewPreferences>();
        builder.Services.AddHttpClient<KeyServerService>();

        // Localization
        builder.Services.AddSingleton<ILanguageStore, MauiLanguageStore>();
        builder.Services.AddSingleton<Loc>();
        builder.Services.AddSingleton<ITutorialStore, MauiTutorialStore>();

        // Platform implementations of the UI abstractions
        builder.Services.AddSingleton<IClipboardService, MauiClipboardService>();
        builder.Services.AddSingleton<IFilePickerService, MauiFilePickerService>();
        builder.Services.AddSingleton<IPlatformInfo, MauiPlatformInfo>();
        builder.Services.AddSingleton(sp => new SecureClipboardService(
            sp.GetRequiredService<IClipboardService>(),
            () => TimeSpan.FromSeconds(
                sp.GetRequiredService<AppSettings>().Get(AppSettingsCatalog.ClipboardClearSeconds))));

#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}
