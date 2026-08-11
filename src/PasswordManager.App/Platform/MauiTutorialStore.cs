using Microsoft.Maui.Storage;
using PasswordManager.UI.Services;

namespace PasswordManager.App.Platform
{
    /// <summary>MAUI implementation of <see cref="ITutorialStore"/> backed by Preferences.</summary>
    public class MauiTutorialStore : ITutorialStore
    {
        /// <summary>The single flag this store used to be, before there was more than one
        /// sequence to remember. Still read — see <see cref="LegacySeen"/>.</summary>
        private const string LegacyKey = "onboarding_tour_seen";

        private const string Prefix = "onboarding_seen_";

        /// <summary>
        /// Unseen sequences fall back to the legacy flag rather than to false. Someone who
        /// finished the old tour has been through the app already, so an update that adds a new
        /// sequence should not greet them with it — only fresh installs, where the legacy flag
        /// was never set, see anything new.
        /// </summary>
        public bool HasSeen(string key) => Preferences.Default.Get(Prefix + key, LegacySeen);

        public void MarkSeen(string key) => Preferences.Default.Set(Prefix + key, true);

        private static bool LegacySeen => Preferences.Default.Get(LegacyKey, false);
    }
}
