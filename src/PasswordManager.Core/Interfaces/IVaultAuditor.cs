using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IVaultAuditor
    {
        /// <summary>
        /// Analyzes already-decrypted password items for weak, reused and expired secrets.
        /// The caller (the service) flattens the vault's <see cref="ServiceEntry"/> credentials
        /// into <see cref="AuditItem"/>s, so the auditor never touches encryption.
        /// </summary>
        AuditReport Audit(IReadOnlyList<AuditItem> items);
    }
}
