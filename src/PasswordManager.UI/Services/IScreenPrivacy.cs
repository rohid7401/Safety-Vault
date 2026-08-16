namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Hides the app's contents from anything outside it: the task-switcher thumbnail,
    /// screenshots, screen recording and casting.
    ///
    /// <para>The two things users asked for — "don't show my open vault in the recents list" and
    /// "don't let it be screenshotted" — are one platform flag on Android, so they are one
    /// setting here rather than two that could disagree.</para>
    ///
    /// <para>Kept on the device rather than in the vault, like the language: the flag has to be
    /// in force before any vault is open, and it describes this screen rather than this account.
    /// The implementation owns its own persistence for the same reason — where the value lives is
    /// a platform question, not a UI one.</para>
    /// </summary>
    public interface IScreenPrivacy
    {
        /// <summary>False where the platform cannot do this, so the UI can say so instead of
        /// offering a switch that does nothing.</summary>
        bool IsSupported { get; }

        bool Enabled { get; }

        void SetEnabled(bool enabled);
    }
}
