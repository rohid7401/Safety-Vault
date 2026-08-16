using PasswordManager.Core.Models;

namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Holds the user's password generation preferences app-wide.
    /// Generator page edits these; vault Add/Edit reuses them.
    /// </summary>
    public class GeneratorPreferences
    {
        public PasswordGeneratorOptions Options { get; } = new()
        {
            Length = 20,
            IncludeUppercase = true,
            IncludeLowercase = true,
            IncludeDigits = true,
            IncludeSpecial = true,
            ExcludeChars = string.Empty,
        };

        /// <summary>
        /// Passphrase settings, kept beside the password ones so switching modes on the generator
        /// page does not lose either. The default word count is not written here: it comes from
        /// the wordlist at startup, so a bigger list shortens the phrase instead of leaving the
        /// default quietly stronger than it needs to be.
        /// </summary>
        public PassphraseGeneratorOptions Phrase { get; } = new();

        /// <summary>Guards that one-time seeding, so reopening the page never quietly resets a
        /// word count the user picked.</summary>
        public bool PhraseDefaultsApplied { get; set; }

        public event Action? OnChanged;

        public void Notify() => OnChanged?.Invoke();
    }
}
