namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Persists the list/grid choice per screen, across launches. Implemented per shell: MAUI
    /// uses Preferences, mirroring <see cref="ITutorialStore"/>.
    /// </summary>
    public interface IViewPreferenceStore
    {
        /// <summary>Returns the stored mode name for a scope, or null if the user never chose.</summary>
        string? Get(string scope);

        void Set(string scope, string mode);
    }
}
