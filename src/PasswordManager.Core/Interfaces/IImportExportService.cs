using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IImportExportService
    {
        string ExportToCsv(IReadOnlyList<PortableEntry> entries);
        List<PortableEntry> ImportFromCsv(string csvContent);
        List<PortableEntry> ImportFromBitwardenJson(string jsonContent);
    }
}
