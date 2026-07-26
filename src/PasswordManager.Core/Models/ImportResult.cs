namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Outcome of parsing an import file. Reported to the user for confirmation
    /// <em>before</em> anything is written, so a file that yields thousands of empty
    /// rows is visible as such instead of silently landing in the vault.
    ///
    /// <para>Exactly one of <see cref="Entries"/> / <see cref="Backup"/> is populated: a flat
    /// file (CSV, Bitwarden) can only produce simple rows, while our own backup carries the
    /// full entry structure and is restored through a different path. The union lives here
    /// rather than in two result types because every caller treats them identically right up
    /// to the final write.</para>
    /// </summary>
    public sealed class ImportResult
    {
        /// <summary>Rows parsed from a flat file. Empty when <see cref="Backup"/> is set.</summary>
        public List<PortableEntry> Entries { get; init; } = new();

        /// <summary>Full-detail native backup. Null when the source was a flat file.</summary>
        public VaultBackup? Backup { get; init; }

        /// <summary>Rows that parsed but held nothing usable, and were dropped.</summary>
        public int SkippedRows { get; init; }

        /// <summary>Values that exceeded <see cref="FieldLimits"/> and were cut to fit.</summary>
        public int TruncatedValues { get; init; }

        /// <summary>True when this came from a SafetyVault backup rather than a flat file.</summary>
        public bool IsNativeBackup => Backup is not null;

        /// <summary>Entries that will be added, whichever shape the source had.</summary>
        public int EntryCount => Backup?.Services.Count ?? Entries.Count;

        /// <summary>
        /// First few entries as "site · account" labels, for the confirmation sheet — enough
        /// for the user to recognise whether this is the file they meant.
        /// </summary>
        public IEnumerable<string> Preview(int take)
        {
            if (Backup is not null)
            {
                return Backup.Services.Take(take).Select(s =>
                {
                    var label = s.Credentials.FirstOrDefault()?.Label ?? string.Empty;
                    return Combine(s.Site, string.IsNullOrWhiteSpace(label) && s.Credentials.Count > 1
                        ? $"{s.Credentials.Count}"
                        : label);
                });
            }

            return Entries.Take(take).Select(e =>
                Combine(e.Site, string.IsNullOrWhiteSpace(e.Username) ? e.Email : e.Username));
        }

        private static string Combine(string site, string detail)
        {
            if (string.IsNullOrWhiteSpace(site)) site = "—";
            return string.IsNullOrWhiteSpace(detail) ? site : $"{site} · {detail}";
        }
    }
}
