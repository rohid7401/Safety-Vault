namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Which one-time onboarding sequences have already been shown, across launches and across
    /// accounts on this device. Implemented per shell: MAUI uses Preferences, mirroring
    /// <see cref="Localization.ILanguageStore"/>.
    /// </summary>
    /// <remarks>
    /// Keyed rather than a single flag: the intro runs before there is an account and the tour
    /// runs after the first unlock, so one boolean could never say that the first had been seen
    /// and the second had not.
    /// </remarks>
    public interface ITutorialStore
    {
        bool HasSeen(string key);
        void MarkSeen(string key);
    }

    /// <summary>Keys for <see cref="ITutorialStore"/>. Values are persisted, so treat them as a
    /// storage format: rename one and the sequence it guards runs again on every device.</summary>
    public static class OnboardingFlags
    {
        /// <summary>What a vault is and how to choose a passphrase, shown before sign-in.</summary>
        public const string Intro = "intro";

        /// <summary>The guided tour of the modules, shown after the first unlock.</summary>
        public const string Tour = "tour";
    }
}
