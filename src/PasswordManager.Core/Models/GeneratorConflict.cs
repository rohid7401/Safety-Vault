namespace PasswordManager.Core.Models
{
    /// <summary>
    /// A way in which the generator options contradict each other and prevent
    /// a password from being produced. The UI maps each value to a message and
    /// offers to auto-resolve it.
    /// </summary>
    public enum GeneratorConflict
    {
        /// <summary>The word to include is longer than the requested total length.</summary>
        WordLongerThanLength,

        /// <summary>The word to include contains a character that is on the exclude list.</summary>
        WordContainsExcludedChars,

        /// <summary>Length beyond the word must be filled, but every character set is disabled (or fully excluded).</summary>
        NoCharacterSetForFiller,
    }
}
