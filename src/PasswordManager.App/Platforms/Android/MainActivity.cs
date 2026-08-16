using Android.App;
using Android.Content.PM;
using Android.OS;
using Android.Views;
using AndroidX.Activity;
using AndroidX.Core.View;
using PasswordManager.App.Platform;
using PasswordManager.UI.Services;
using AView = Android.Views.View;

namespace PasswordManager.App;

// WindowSoftInputMode = AdjustResize shrinks the WebView viewport when the soft
// keyboard opens, so a focused field inside a bottom sheet can scroll into view
// instead of being hidden behind the keyboard.
[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true,
    WindowSoftInputMode = SoftInput.AdjustResize | SoftInput.StateHidden,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // Apps targeting API 35+ get edge-to-edge forced by the OS — the old
        // Window.SetDecorFitsSystemWindows(true) opt-out is ignored on these targets. Without
        // this, the WebView draws under the status bar and gesture/navigation bar. Padding the
        // content root by the system bar insets restores the old inset-from-the-bars look.
        // Before anything is drawn, so the window is never captured unprotected — not even for
        // the frame between launch and the first render.
        if (IPlatformApplication.Current?.Services.GetService<IScreenPrivacy>() is MauiScreenPrivacy privacy)
            privacy.Apply();

        var rootView = Window!.DecorView.FindViewById(Android.Resource.Id.Content)!;
        ViewCompat.SetOnApplyWindowInsetsListener(rootView, new SystemBarsInsetsListener());

        // Back has to be claimed through the dispatcher, not MAUI's Page.OnBackButtonPressed.
        // From API 35 the platform turns on predictive back by default, and that path never
        // reaches the legacy callback — so the in-app bridge went dead the moment this project
        // moved to API 36, and every press closed the app from wherever the user was.
        OnBackPressedDispatcher.AddCallback(this, new ShellBackCallback(this));
    }

    /// <summary>
    /// Hands the press to the Blazor router when the shell says there is somewhere to go, and
    /// otherwise steps aside so the platform can do what back normally does — leave.
    /// </summary>
    private sealed class ShellBackCallback : OnBackPressedCallback
    {
        private readonly MainActivity _activity;

        public ShellBackCallback(MainActivity activity) : base(true) => _activity = activity;

        public override void HandleOnBackPressed()
        {
            var back = IPlatformApplication.Current?.Services.GetService<ShellBackNavigation>();
            if (back is not null && back.TryHandleBack()) return;

            // Not ours. Disabling this callback and re-dispatching lets the default handling run;
            // re-enabling afterwards puts us back in line for the next press. Calling
            // Finish() instead would skip whatever else is registered, predictive back included.
            var dispatcher = _activity.OnBackPressedDispatcher;
            if (dispatcher is null) { _activity.Finish(); return; }

            Enabled = false;
            dispatcher.OnBackPressed();
            Enabled = true;
        }
    }

    /// <summary>Pads a view by the current system bar insets. A Java interface binding, not a
    /// delegate, so it needs a class rather than a lambda.</summary>
    private sealed class SystemBarsInsetsListener : Java.Lang.Object, IOnApplyWindowInsetsListener
    {
        public WindowInsetsCompat? OnApplyWindowInsets(AView? v, WindowInsetsCompat? insets)
        {
            if (v is null || insets is null) return insets;
            var systemBars = insets.GetInsets(WindowInsetsCompat.Type.SystemBars());
            v.SetPadding(systemBars.Left, systemBars.Top, systemBars.Right, systemBars.Bottom);
            return insets;
        }
    }
}
