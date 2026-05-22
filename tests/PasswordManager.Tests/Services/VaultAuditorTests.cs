using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class VaultAuditorTests
    {
        private readonly VaultAuditor _auditor = new(new PasswordGenerator());

        [Fact]
        public void Audit_EmptyList_ReturnsEmptyReport()
        {
            var report = _auditor.Audit(Array.Empty<PasswordEntry>(), _ => "");
            Assert.Equal(0, report.TotalPasswords);
            Assert.Empty(report.Issues);
        }

        [Fact]
        public void Audit_WeakPassword_DetectsWeakness()
        {
            var entries = new[]
            {
                new PasswordEntry { Site = "test.com" }
            };

            var report = _auditor.Audit(entries, _ => "abc");

            Assert.Equal(1, report.WeakCount);
            Assert.Contains(report.Issues, i => i.Type == AuditIssueType.WeakPassword);
        }

        [Fact]
        public void Audit_StrongPassword_NoWeaknessIssues()
        {
            var entries = new[]
            {
                new PasswordEntry { Site = "test.com" }
            };

            var report = _auditor.Audit(entries, _ => "Str0ng!P@ssw0rd#2024XyZ");

            Assert.Equal(0, report.WeakCount);
            Assert.DoesNotContain(report.Issues, i => i.Type == AuditIssueType.WeakPassword);
        }

        [Fact]
        public void Audit_ReusedPasswords_DetectsReuse()
        {
            var entries = new[]
            {
                new PasswordEntry { Site = "site1.com" },
                new PasswordEntry { Site = "site2.com" },
                new PasswordEntry { Site = "site3.com" }
            };

            var report = _auditor.Audit(entries, _ => "SamePassword123!");

            Assert.Equal(3, report.ReusedCount);
            Assert.Contains(report.Issues, i => i.Type == AuditIssueType.ReusedPassword);
        }

        [Fact]
        public void Audit_UniquePasswords_NoReuseIssues()
        {
            var passwords = new Dictionary<Guid, string>();
            var entries = new[]
            {
                new PasswordEntry { Site = "site1.com" },
                new PasswordEntry { Site = "site2.com" }
            };
            passwords[entries[0].Id] = "UniquePass1!Xyz";
            passwords[entries[1].Id] = "UniquePass2!Abc";

            var report = _auditor.Audit(entries, e => passwords[e.Id]);

            Assert.Equal(0, report.ReusedCount);
        }

        [Fact]
        public void Audit_ExpiredEntry_DetectsExpiration()
        {
            var entries = new[]
            {
                new PasswordEntry
                {
                    Site = "expired.com",
                    ExpireTime = DateTime.UtcNow.AddDays(-30)
                }
            };

            var report = _auditor.Audit(entries, _ => "Str0ng!P@ssw0rd#2024XyZ");

            Assert.Equal(1, report.ExpiredCount);
            Assert.Contains(report.Issues, i => i.Type == AuditIssueType.ExpiredEntry);
        }

        [Fact]
        public void Audit_FutureExpiry_NoExpirationIssues()
        {
            var entries = new[]
            {
                new PasswordEntry
                {
                    Site = "valid.com",
                    ExpireTime = DateTime.UtcNow.AddDays(90)
                }
            };

            var report = _auditor.Audit(entries, _ => "Str0ng!P@ssw0rd#2024XyZ");

            Assert.Equal(0, report.ExpiredCount);
        }

        [Fact]
        public void Audit_MultipleIssues_ReportsAll()
        {
            var entries = new[]
            {
                new PasswordEntry { Site = "weak.com" },
                new PasswordEntry { Site = "reused1.com" },
                new PasswordEntry { Site = "reused2.com" },
                new PasswordEntry { Site = "expired.com", ExpireTime = DateTime.UtcNow.AddDays(-1) }
            };

            var passwords = new Dictionary<Guid, string>
            {
                [entries[0].Id] = "123",
                [entries[1].Id] = "SharedPass!Xyz1",
                [entries[2].Id] = "SharedPass!Xyz1",
                [entries[3].Id] = "Str0ng!P@ssw0rd#2024XyZ"
            };

            var report = _auditor.Audit(entries, e => passwords[e.Id]);

            Assert.Equal(4, report.TotalPasswords);
            Assert.True(report.WeakCount > 0);
            Assert.True(report.ReusedCount > 0);
            Assert.True(report.ExpiredCount > 0);
        }
    }
}
