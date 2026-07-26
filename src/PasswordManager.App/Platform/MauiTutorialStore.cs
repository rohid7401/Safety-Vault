using Microsoft.Maui.Storage;
using PasswordManager.UI.Services;

namespace PasswordManager.App.Platform
{
    /// <summary>MAUI implementation of <see cref="ITutorialStore"/> backed by Preferences.</summary>
    public class MauiTutorialStore : ITutorialStore
    {
        private const string Key = "onboarding_tour_seen";

        public bool HasSeenTutorial() => Preferences.Default.Get(Key, false);

        public void MarkTutorialSeen() => Preferences.Default.Set(Key, true);
    }
}
