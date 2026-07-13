using Android.App;
using Android.Content.PM;
using Android.OS;
using Android.Views;

namespace PasswordManager.App;

// WindowSoftInputMode = AdjustResize shrinks the WebView viewport when the soft
// keyboard opens, so a focused field inside a bottom sheet can scroll into view
// instead of being hidden behind the keyboard.
[Activity(Theme = "@style/Maui.SplashTheme", MainLauncher = true,
    WindowSoftInputMode = SoftInput.AdjustResize | SoftInput.StateHidden,
    ConfigurationChanges = ConfigChanges.ScreenSize | ConfigChanges.Orientation | ConfigChanges.UiMode | ConfigChanges.ScreenLayout | ConfigChanges.SmallestScreenSize | ConfigChanges.Density)]
public class MainActivity : MauiAppCompatActivity
{
}
