using Microsoft.Maui.Storage;
using PasswordManager.UI.Services;

#if ANDROID
using Android.Views;
#endif

namespace PasswordManager.App.Platform
{
    /// <summary>
    /// MAUI implementation of <see cref="IScreenPrivacy"/>. On Android this is FLAG_SECURE, which
    /// blanks the recents thumbnail and blocks screenshots, recording and casting in one go.
    /// Elsewhere it reports unsupported rather than pretending.
    /// </summary>
    public class MauiScreenPrivacy : IScreenPrivacy
    {
        private const string Key = "screen_privacy";

#if ANDROID
        public bool IsSupported => true;
#else
        public bool IsSupported => false;
#endif

        /// <summary>
        /// On by default. This is a password manager, so an open vault sitting in the task
        /// switcher is a real exposure and the safer default is the one that costs a user
        /// nothing but the ability to screenshot — which the switch gives back.
        /// </summary>
        public bool Enabled => IsSupported && Preferences.Default.Get(Key, true);

        public void SetEnabled(bool enabled)
        {
            if (!IsSupported) return;
            Preferences.Default.Set(Key, enabled);
            Apply(enabled);
        }

        /// <summary>Re-asserts the current setting on the live window. Called at startup, before
        /// anything is drawn, and again whenever the switch is flipped.</summary>
        public void Apply() => Apply(Enabled);

        private static void Apply(bool enabled)
        {
#if ANDROID
            // Window flags are UI-thread only, and this is called from the settings page as well
            // as from activity startup.
            MainThread.BeginInvokeOnMainThread(() =>
            {
                var window = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity?.Window;
                if (window is null) return;
                if (enabled) window.AddFlags(WindowManagerFlags.Secure);
                else window.ClearFlags(WindowManagerFlags.Secure);
            });
#endif
        }
    }
}
