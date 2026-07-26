namespace PasswordManager.Core.Models
{
    /// <summary>What the export is aimed at. Drives the column set and the header names.</summary>
    public enum ExportTarget
    {
        /// <summary>SafetyVault's own lossless JSON backup — device to device.</summary>
        NativeBackup,

        /// <summary>Readable CSV with our own header names; also what this app re-imports best.</summary>
        GenericCsv,

        /// <summary>CSV with the exact headers Bitwarden's importer expects.</summary>
        BitwardenCsv,

        /// <summary>CSV with the headers Chrome, Edge and Google Password Manager expect.</summary>
        ChromeCsv,
    }

    /// <summary>
    /// One column of a CSV export: the header written out, and where its value comes from.
    /// </summary>
    /// <param name="Header">Header text. Fixed by the target format — Bitwarden will not
    /// recognise <c>password</c> where it expects <c>login_password</c>.</param>
    /// <param name="Field">Value to pull from the row, or null for a <see cref="Constant"/>.</param>
    /// <param name="Constant">Literal written in every row. Used for the structural columns a
    /// target requires but that carry no user data (Bitwarden's <c>type</c>, <c>reprompt</c>).</param>
    public sealed record ExportColumn(string Header, ExportField? Field, string Constant = "")
    {
        /// <summary>
        /// Structural columns are not offered as checkboxes: they carry no user data, and
        /// dropping them only breaks the target's parser.
        /// </summary>
        public bool IsSelectable => Field.HasValue;
    }

    /// <summary>The column layout each <see cref="ExportTarget"/> writes.</summary>
    public static class ExportPresets
    {
        /// <summary>
        /// Our own CSV. <c>credential_label</c> is what keeps two accounts of the same service
        /// distinguishable once they are separate rows, and the remaining names match the
        /// aliases the importer already understands, so an export re-imports cleanly.
        /// </summary>
        private static readonly ExportColumn[] Generic =
        {
            new("site", ExportField.Site),
            new("credential_label", ExportField.CredentialLabel),
            new("username", ExportField.Username),
            new("email", ExportField.Email),
            new("password", ExportField.Password),
            new("pin", ExportField.Pin),
            new("phone", ExportField.Phone),
            new("url", ExportField.Web),
            new("totp_secret", ExportField.TotpSecret),
            new("notes", ExportField.Text),
            new("tags", ExportField.Tags),
        };

        /// <summary>
        /// Bitwarden's import columns. <c>type</c> and <c>reprompt</c> are constants because
        /// every row we produce is a login that does not re-prompt; <c>folder</c> carries our
        /// tags, which is the closest thing Bitwarden has to them.
        /// </summary>
        private static readonly ExportColumn[] Bitwarden =
        {
            new("folder", ExportField.Tags),
            new("favorite", null),
            new("type", null, "login"),
            new("name", ExportField.Site),
            new("notes", ExportField.Text),
            new("fields", null),
            new("reprompt", null, "0"),
            new("login_uri", ExportField.Web),
            new("login_username", ExportField.Login),
            new("login_password", ExportField.Password),
            new("login_totp", ExportField.TotpSecret),
        };

        /// <summary>Chrome / Edge / Google Password Manager import columns.</summary>
        private static readonly ExportColumn[] Chrome =
        {
            new("name", ExportField.Site),
            new("url", ExportField.Web),
            new("username", ExportField.Login),
            new("password", ExportField.Password),
            new("note", ExportField.Text),
        };

        public static IReadOnlyList<ExportColumn> For(ExportTarget target) => target switch
        {
            ExportTarget.BitwardenCsv => Bitwarden,
            ExportTarget.ChromeCsv => Chrome,
            _ => Generic,
        };

        /// <summary>Fields a target can carry, in column order — the checkbox list shown to the user.</summary>
        public static IReadOnlyList<ExportField> SelectableFields(ExportTarget target) =>
            For(target).Where(c => c.IsSelectable).Select(c => c.Field!.Value).Distinct().ToList();
    }
}
