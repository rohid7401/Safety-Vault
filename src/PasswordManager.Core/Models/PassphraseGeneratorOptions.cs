namespace PasswordManager.Core.Models
{
    /// <summary>
    /// A passphrase is words joined by a separator — <c>puente-canela-brujula-nogal</c> — and its
    /// strength comes from how many words there are and how big the list is, never from what the
    /// words look like. Anything here that does not change one of those two numbers changes how
    /// the phrase reads and nothing else, which is why capitalisation is not a security option.
    /// </summary>
    public class PassphraseGeneratorOptions
    {
        public int WordCount { get; set; } = 6;

        public string Separator { get; set; } = "-";

        /// <summary>Cosmetic. Worth nothing in entropy and quite a lot in readability.</summary>
        public bool Capitalize { get; set; } = true;

        /// <summary>
        /// Appends a digit to one of the words, for the sites that insist on a number. Worth
        /// about 3.3 bits, which is why it is off by default: adding a word is worth three times
        /// as much and is easier to remember.
        /// </summary>
        public bool IncludeNumber { get; set; }
    }
}
