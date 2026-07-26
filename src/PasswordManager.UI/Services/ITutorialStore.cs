namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Persists whether the first-run guided tour has already been shown, across launches
    /// and across accounts on this device. Implemented per shell: MAUI uses Preferences,
    /// mirroring <see cref="Localization.ILanguageStore"/>.
    /// </summary>
    public interface ITutorialStore
    {
        bool HasSeenTutorial();
        void MarkTutorialSeen();
    }
}
