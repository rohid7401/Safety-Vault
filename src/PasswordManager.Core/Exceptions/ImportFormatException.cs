namespace PasswordManager.Core.Exceptions
{
    /// <summary>Why an import was rejected before any entry was written to the vault.</summary>
    public enum ImportFormatError
    {
        /// <summary>File is larger than <see cref="Models.ImportLimits.MaxFileBytes"/>.</summary>
        FileTooLarge,

        /// <summary>Binary content — not decodable as UTF-8 text.</summary>
        NotText,

        /// <summary>
        /// A PGP block (encrypted, signed, or a key). Importing one as plaintext used to
        /// turn each line of base64 into an empty entry, so it is refused outright.
        /// </summary>
        PgpBlock,

        /// <summary>No column in the CSV header matched a field we understand.</summary>
        UnrecognizedColumns,

        /// <summary>Content is not valid JSON / not a Bitwarden export.</summary>
        InvalidJson,

        /// <summary>More entries than <see cref="Models.ImportLimits.MaxEntries"/>.</summary>
        TooManyEntries,

        /// <summary>Parsed cleanly but produced no usable entry.</summary>
        NoUsableEntries,

        /// <summary>
        /// A SafetyVault backup written by a newer version. Refused rather than imported
        /// partially: silently dropping fields this build does not know about is worse on a
        /// "restore my vault" path than asking the user to update.
        /// </summary>
        UnsupportedVersion,
    }

    /// <summary>
    /// Thrown when a file offered for import is not the format it claims to be. Carries a
    /// machine-readable <see cref="Reason"/> so the UI can show a translated explanation
    /// (the message here is for logs, not for the screen).
    /// </summary>
    public class ImportFormatException : Exception
    {
        public ImportFormatError Reason { get; }

        public ImportFormatException(ImportFormatError reason)
            : base($"Import rejected: {reason}")
        {
            Reason = reason;
        }
    }
}
