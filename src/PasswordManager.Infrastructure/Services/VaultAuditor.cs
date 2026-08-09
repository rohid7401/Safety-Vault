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

        public AuditReport Audit(IReadOnlyList<AuditItem> items)
        {
            var report = new AuditReport { TotalPasswords = items.Count };

            CheckWeakPasswords(items, report);
            CheckReusedPasswords(items, report);
            CheckExpiredEntries(items, report);

            return report;
        }

        private void CheckWeakPasswords(IReadOnlyList<AuditItem> items, AuditReport report)
        {
            foreach (var item in items)
            {
                if (!item.StrengthChecked) continue;

                var strength = _passwordGenerator.CalculateStrength(item.Password);
                if (strength >= 5) continue;

                report.WeakCount++;
                report.Issues.Add(new AuditIssue
                {
                    EntryId = item.EntryId,
                    EntryLabel = item.Label,
                    Type = AuditIssueType.WeakPassword,
                    Severity = strength <= 2 ? AuditSeverity.Critical : AuditSeverity.High,
                    Strength = strength
                });
            }
        }

        private static void CheckReusedPasswords(IReadOnlyList<AuditItem> items, AuditReport report)
        {
            var grouped = items
                .Where(i => !string.IsNullOrEmpty(i.Password))
                .GroupBy(i => i.Password)
                .Where(g => g.Count() > 1);

            foreach (var group in grouped)
            {
                foreach (var item in group)
                {
                    report.ReusedCount++;
                    report.Issues.Add(new AuditIssue
                    {
                        EntryId = item.EntryId,
                        EntryLabel = item.Label,
                        Type = AuditIssueType.ReusedPassword,
                        Severity = AuditSeverity.High,
                        SharedWith = group.Count() - 1
                    });
                }
            }
        }

        private static void CheckExpiredEntries(IReadOnlyList<AuditItem> items, AuditReport report)
        {
            var now = DateTime.UtcNow;
            foreach (var item in items)
            {
                if (item.ExpiresAt.HasValue && item.ExpiresAt.Value < now)
                {
                    report.ExpiredCount++;
                    report.Issues.Add(new AuditIssue
                    {
                        EntryId = item.EntryId,
                        EntryLabel = item.Label,
                        Type = AuditIssueType.ExpiredEntry,
                        Severity = AuditSeverity.Medium,
                        ExpiredOn = item.ExpiresAt.Value
                    });
                }
            }
        }
    }
}
