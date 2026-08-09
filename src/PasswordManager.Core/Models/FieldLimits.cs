namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Canonical maximum lengths for user-entered values, in characters.
    ///
    /// These are the single source of truth shared by the two places that must agree:
    /// the input fields (which cap what can be typed or pasted) and the importer
    /// (which caps what an outside file can inject, where no <c>maxlength</c> applies).
    /// They exist to keep a malformed or hostile file from filling the vault with
    /// megabyte-sized values, not as security boundaries.
    /// </summary>
    public static class FieldLimits
    {
        /// <summary>RFC 5321 maximum length of an email address.</summary>
        public const int Email = 254;

        public const int Username = 100;
        public const int Password = 128;
        public const int Pin = 12;
        public const int Phone = 20;
        public const int TwoFactorSecret = 128;

        /// <summary>API keys and access tokens run far longer than a password — a signed JWT is
        /// routinely several hundred characters — so the cap sits well above anything real.</summary>
        public const int ApiKey = 1_000;

        /// <summary>Generic free-text credential field.</summary>
        public const int Text = 200;

        /// <summary>Entry/credential display names, service names, contact labels.</summary>
        public const int Label = 120;

        /// <summary>Site or URL.</summary>
        public const int Site = 300;

        public const int NoteTitle = 120;
        public const int NoteContent = 20_000;

        public const int CardholderName = 100;
        public const int CardNumber = 25;
        public const int Cvv = 4;

        public const int Tag = 40;
        public const int TagsPerEntry = 20;

        /// <summary>Truncates <paramref name="value"/> to <paramref name="max"/> characters.</summary>
        public static string Clamp(string? value, int max)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            return value.Length <= max ? value : value[..max];
        }
    }
}
