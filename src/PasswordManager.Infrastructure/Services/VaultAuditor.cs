using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    public class VaultAuditor : IVaultAuditor
    {
        private readonly IPasswordGenerator _passwordGenerator;

        public VaultAuditor(IPasswordGenerator passwordGenerator)
        {
            _passwordGenerator = passwordGenerator;
        }

        public AuditReport Audit(IReadOnlyList<PasswordEntry> entries, Func<PasswordEntry, string> decryptor)
        {
            var report = new AuditReport { TotalPasswords = entries.Count };
            var decryptedPasswords = new Dictionary<Guid, string>();

            foreach (var entry in entries)
                decryptedPasswords[entry.Id] = decryptor(entry);

            CheckWeakPasswords(entries, decryptedPasswords, report);
            CheckReusedPasswords(entries, decryptedPasswords, report);
            CheckExpiredEntries(entries, report);

            return report;
        }

        private void CheckWeakPasswords(
            IReadOnlyList<PasswordEntry> entries,
            Dictionary<Guid, string> passwords,
            AuditReport report)
        {
            foreach (var entry in entries)
            {
                var strength = _passwordGenerator.CalculateStrength(passwords[entry.Id]);
                if (strength >= 5) continue;

                report.WeakCount++;
                report.Issues.Add(new AuditIssue
                {
                    EntryId = entry.Id,
                    EntryLabel = entry.Site,
                    Type = AuditIssueType.WeakPassword,
                    Severity = strength <= 2 ? AuditSeverity.Critical : AuditSeverity.High,
                    Description = $"Password strength: {strength}/8"
                });
            }
        }

        private static void CheckReusedPasswords(
            IReadOnlyList<PasswordEntry> entries,
            Dictionary<Guid, string> passwords,
            AuditReport report)
        {
            var grouped = entries
                .GroupBy(e => passwords[e.Id])
                .Where(g => g.Count() > 1);

            foreach (var group in grouped)
            {
                foreach (var entry in group)
                {
                    report.ReusedCount++;
                    report.Issues.Add(new AuditIssue
                    {
                        EntryId = entry.Id,
                        EntryLabel = entry.Site,
                        Type = AuditIssueType.ReusedPassword,
                        Severity = AuditSeverity.High,
                        Description = $"Password shared with {group.Count() - 1} other entries"
                    });
                }
            }
        }

        private static void CheckExpiredEntries(IReadOnlyList<PasswordEntry> entries, AuditReport report)
        {
            var now = DateTime.UtcNow;
            foreach (var entry in entries)
            {
                if (entry.ExpireTime.HasValue && entry.ExpireTime.Value < now)
                {
                    report.ExpiredCount++;
                    report.Issues.Add(new AuditIssue
                    {
                        EntryId = entry.Id,
                        EntryLabel = entry.Site,
                        Type = AuditIssueType.ExpiredEntry,
                        Severity = AuditSeverity.Medium,
                        Description = $"Expired on {entry.ExpireTime.Value:yyyy-MM-dd}"
                    });
                }
            }
        }
    }
}
