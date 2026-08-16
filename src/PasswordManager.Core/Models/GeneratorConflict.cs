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

        /// <summary>A count range is inverted — its minimum is above its maximum.</summary>
        CountRangeInverted,

        /// <summary>The minimums add up to more than the password is long.</summary>
        MinimumsExceedLength,

        /// <summary>
        /// The maximums leave the password short: every class is either capped or switched off,
        /// and their caps together cannot fill the requested length.
        /// </summary>
        MaximumsBelowLength,

        /// <summary>A class is capped or has a minimum, but that class is switched off entirely.</summary>
        LimitOnDisabledSet,

        /// <summary>The word to include already carries more digits or symbols than the cap allows.</summary>
        WordExceedsCount,
    }
}
