using Android.App;
using Android.Content.PM;
using Android.OS;
using Android.Views;
using AndroidX.Core.View;
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
        var rootView = Window!.DecorView.FindViewById(Android.Resource.Id.Content)!;
        ViewCompat.SetOnApplyWindowInsetsListener(rootView, new SystemBarsInsetsListener());
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
