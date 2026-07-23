using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class VaultAuditorTests
    {
        private readonly VaultAuditor _auditor = new(new PasswordGenerator());

        private static AuditItem Item(string password, DateTime? expiresAt = null, string label = "test.com") =>
            new() { EntryId = Guid.NewGuid(), Label = label, Password = password, ExpiresAt = expiresAt };

        [Fact]
        public void Audit_EmptyList_ReturnsEmptyReport()
        {
            var report = _auditor.Audit(Array.Empty<AuditItem>());
            Assert.Equal(0, report.TotalPasswords);
            Assert.Empty(report.Issues);
        }

        [Fact]
        public void Audit_WeakPassword_DetectsWeakness()
        {
            var report = _auditor.Audit(new[] { Item("abc") });

            Assert.Equal(1, report.WeakCount);
            Assert.Contains(report.Issues, i => i.Type == AuditIssueType.WeakPassword);
        }

        [Fact]
        public void Audit_StrongPassword_NoWeaknessIssues()
        {
            var report = _auditor.Audit(new[] { Item("Str0ng!P@ssw0rd#2024XyZ") });

            Assert.Equal(0, report.WeakCount);
            Assert.DoesNotContain(report.Issues, i => i.Type == AuditIssueType.WeakPassword);
        }

        [Fact]
        public void Audit_ReusedPasswords_DetectsReuse()
        {
            var report = _auditor.Audit(new[]
            {
                Item("SamePassword123!", label: "site1.com"),
                Item("SamePassword123!", label: "site2.com"),
                Item("SamePassword123!", label: "site3.com"),
            });

            Assert.Equal(3, report.ReusedCount);
            Assert.Contains(report.Issues, i => i.Type == AuditIssueType.ReusedPassword);
        }

        [Fact]
        public void Audit_UniquePasswords_NoReuseIssues()
        {
            var report = _auditor.Audit(new[]
            {
                Item("UniquePass1!Xyz", label: "site1.com"),
                Item("UniquePass2!Abc", label: "site2.com"),
            });

            Assert.Equal(0, report.ReusedCount);
        }

        [Fact]
        public void Audit_EmptyPasswords_NotFlaggedAsReused()
        {
            var report = _auditor.Audit(new[]
            {
                Item("", label: "a.com"),
                Item("", label: "b.com"),
            });

            Assert.Equal(0, report.ReusedCount);
        }

        [Fact]
        public void Audit_ExpiredEntry_DetectsExpiration()
        {
            var report = _auditor.Audit(new[]
            {
                Item("Str0ng!P@ssw0rd#2024XyZ", DateTime.UtcNow.AddDays(-30), "expired.com"),
            });

            Assert.Equal(1, report.ExpiredCount);
            Assert.Contains(report.Issues, i => i.Type == AuditIssueType.ExpiredEntry);
        }

        [Fact]
        public void Audit_FutureExpiry_NoExpirationIssues()
        {
            var report = _auditor.Audit(new[]
            {
                Item("Str0ng!P@ssw0rd#2024XyZ", DateTime.UtcNow.AddDays(90), "valid.com"),
            });

            Assert.Equal(0, report.ExpiredCount);
        }

        [Fact]
        public void Audit_MultipleIssues_ReportsAll()
        {
            var report = _auditor.Audit(new[]
            {
                Item("123", label: "weak.com"),
                Item("SharedPass!Xyz1", label: "reused1.com"),
                Item("SharedPass!Xyz1", label: "reused2.com"),
                Item("Str0ng!P@ssw0rd#2024XyZ", DateTime.UtcNow.AddDays(-1), "expired.com"),
            });

            Assert.Equal(4, report.TotalPasswords);
            Assert.True(report.WeakCount > 0);
            Assert.True(report.ReusedCount > 0);
            Assert.True(report.ExpiredCount > 0);
        }
    }
}
