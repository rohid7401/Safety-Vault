using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    /// <summary>
    /// Word-based generation: passphrases, and the usernames that fall out of the same list.
    /// Kept together because both are only as good as the wordlist behind them, and one owner
    /// means one place where that list is loaded and counted.
    /// </summary>
    public interface IPassphraseGenerator
    {
        /// <summary>
        /// A passphrase in the given language, falling back to the first list available when
        /// there is none for it — a phrase in the wrong language beats no phrase at all.
        /// </summary>
        string Generate(string language, PassphraseGeneratorOptions? options = null);

        /// <summary>
        /// A two-word handle with a number, e.g. <c>puente-canela-47</c>. Not a security feature:
        /// the point is not reusing the same identifier everywhere, so it is short and readable.
        /// </summary>
        string GenerateUsername(string language);

        /// <summary>
        /// How much guessing the phrase would actually cost, computed from the real size of the
        /// loaded list. Read straight from the data so the figure on screen cannot drift from
        /// the words behind it — if the list grows, this rises on its own.
        /// </summary>
        double EntropyBits(string language, PassphraseGeneratorOptions options);

        /// <summary>Number of distinct words available for a language.</summary>
        int WordCount(string language);

        /// <summary>
        /// The shortest phrase that reaches <paramref name="targetBits"/> with this list. The
        /// default word count comes from here rather than from a constant, so a bigger list
        /// shortens the phrase instead of quietly making the default stronger than it needs.
        /// </summary>
        int WordsForStrength(string language, double targetBits);
    }
}
