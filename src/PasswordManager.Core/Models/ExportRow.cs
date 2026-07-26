namespace PasswordManager.Core.Models
{
    /// <summary>
    /// One <see cref="Credential"/> flattened for a spreadsheet-shaped export — one row per
    /// account, not per service, so a card holding "Personal" and "Work" produces two rows
    /// that <see cref="CredentialLabel"/> tells apart.
    ///
    /// <para>Richer than <see cref="PortableEntry"/> (which only carries what the importer can
    /// read back) because an export to another manager may legitimately include values this app
    /// would not re-import from a flat file, such as PINs and phone numbers. Anything the target
    /// format has no column for is simply left out by the column selection.</para>
    /// </summary>
    public sealed class ExportRow
    {
        public string Site { get; set; } = string.Empty;
        public string CredentialLabel { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Pin { get; set; } = string.Empty;
        public string Phone { get; set; } = string.Empty;
        public string TotpSecret { get; set; } = string.Empty;

        /// <summary>Free-text fields joined together; lands in the target's "notes" column.</summary>
        public string Text { get; set; } = string.Empty;

        public string Tags { get; set; } = string.Empty;

        /// <summary>
        /// Whatever identifies the account, for targets with a single login column. Most
        /// credentials here sign in with an email and carry no separate username, so a
        /// Username-only mapping would export an empty column for nearly every row.
        /// </summary>
        public string Login => string.IsNullOrEmpty(Username) ? Email : Username;

        public string ValueOf(ExportField field) => field switch
        {
            ExportField.Site => Site,
            ExportField.CredentialLabel => CredentialLabel,
            ExportField.Username => Username,
            ExportField.Email => Email,
            ExportField.Login => Login,
            ExportField.Password => Password,
            ExportField.Pin => Pin,
            ExportField.Phone => Phone,
            ExportField.TotpSecret => TotpSecret,
            ExportField.Text => Text,
            ExportField.Tags => Tags,
            _ => string.Empty,
        };
    }

    /// <summary>A value an export column can be filled from.</summary>
    public enum ExportField
    {
        Site,
        CredentialLabel,
        Username,
        Email,

        /// <summary>Username, falling back to email. For targets with one login column.</summary>
        Login,

        Password,
        Pin,
        Phone,
        TotpSecret,
        Text,
        Tags,
    }
}
