namespace PasswordManager.UI.Localization
{
    /// <summary>
    /// Persists the user's chosen UI language across launches. Implemented per shell:
    /// MAUI uses Preferences; a future web shell would use localStorage.
    /// </summary>
    public interface ILanguageStore
    {
        /// <summary>The saved two-letter language code (e.g. "es"), or null if none set.</summary>
        string? GetSavedLanguage();

        /// <summary>Persist the chosen two-letter language code.</summary>
        void SaveLanguage(string code);
    }
}
