namespace PasswordManager.Core.Models
{
    public class PasswordGeneratorOptions
    {
        public int Length { get; set; } = 20;
        public bool IncludeUppercase { get; set; } = true;
        public bool IncludeLowercase { get; set; } = true;
        public bool IncludeDigits { get; set; } = true;
        public bool IncludeSpecial { get; set; } = true;
        public string ExcludeChars { get; set; } = string.Empty;

        /// <summary>
        /// Drops the glyphs that are read wrong when a password is copied off a screen onto
        /// paper, or off paper into a keyboard: <c>0/O</c> and <c>1/l/I/|</c>. Applied on top of
        /// <see cref="ExcludeChars"/> rather than into it, so turning it off gives back exactly
        /// the characters it removed and leaves the user's own list alone.
        /// </summary>
        public bool ExcludeAmbiguous { get; set; }

        /// <summary>
        /// Bounds the count of digits, for the sites that demand "at least two numbers" and the
        /// ones that refuse more than a couple. Off means the digits fall where chance puts
        /// them, which is what it has always done.
        /// </summary>
        /// <remarks>
        /// A pair of plain ints behind a switch rather than two nullables: "no minimum" and
        /// "minimum of none" are the same thing to a user and different things to a nullable,
        /// and the difference only ever shows up as a bug.
        /// </remarks>
        public bool LimitDigits { get; set; }

        public int MinDigits { get; set; } = 1;
        public int MaxDigits { get; set; } = 4;

        /// <summary>The same, for the special characters.</summary>
        public bool LimitSpecial { get; set; }

        public int MinSpecial { get; set; } = 1;
        public int MaxSpecial { get; set; } = 4;

        /// <summary>
        /// Optional literal word to embed inside every generated password (e.g. "yuki").
        /// Inserted verbatim at a random position; the remaining length is filled randomly.
        /// </summary>
        public string IncludeWord { get; set; } = string.Empty;
    }
}
