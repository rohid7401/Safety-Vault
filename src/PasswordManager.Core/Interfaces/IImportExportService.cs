using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IImportExportService
    {
        // ─── Export ──────────────────────────────────────────────────────────

        /// <summary>
        /// Writes the given rows as CSV using exactly the columns supplied — their headers,
        /// their order, and nothing else. The caller picks those from
        /// <see cref="ExportPresets"/> and whatever the user chose to leave out.
        /// </summary>
        string ExportToCsv(IReadOnlyList<ExportRow> rows, IReadOnlyList<ExportColumn> columns);

        /// <summary>Serialises a lossless <see cref="VaultBackup"/>. Wrap it in PGP before saving.</summary>
        string ExportToBackupJson(VaultBackup backup);

        // ─── Import ──────────────────────────────────────────────────────────

        /// <summary>
        /// Detects the format from the content and parses accordingly. Throws
        /// <see cref="Exceptions.ImportFormatException"/> if it is not a recognisable export —
        /// nothing is written to the vault here, so the caller can show the result and ask for
        /// confirmation first.
        /// </summary>
        ImportResult Import(string content);

        /// <inheritdoc cref="Import"/>
        ImportResult ImportFromCsv(string csvContent);

        /// <inheritdoc cref="Import"/>
        ImportResult ImportFromBitwardenJson(string jsonContent);

        /// <inheritdoc cref="Import"/>
        ImportResult ImportFromBackupJson(string jsonContent);
    }
}
