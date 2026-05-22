using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IVaultAuditor
    {
        AuditReport Audit(IReadOnlyList<PasswordEntry> entries, Func<PasswordEntry, string> decryptor);
    }
}
