namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Ceilings applied to an import before anything reaches the vault. A real export
    /// from another password manager sits far below all of these; hitting one means the
    /// file is not what the user thinks it is.
    /// </summary>
    public static class ImportLimits
    {
        /// <summary>Largest file accepted for import. A 5 MB CSV is already ~50k entries.</summary>
        public const int MaxFileBytes = 5 * 1024 * 1024;

        /// <summary>Largest number of entries a single import may add.</summary>
        public const int MaxEntries = 5_000;

        /// <summary>
        /// Rows read from a CSV before giving up. Guards against a file that is not a CSV
        /// at all (a signature block, a log, a minified blob) being walked line by line.
        /// </summary>
        public const int MaxRows = 50_000;
    }
}
