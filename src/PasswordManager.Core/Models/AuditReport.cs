namespace PasswordManager.Core.Models
{
    public class AuditReport
    {
        public List<AuditIssue> Issues { get; set; } = new();
        public int TotalPasswords { get; set; }
        public int WeakCount { get; set; }
        public int ReusedCount { get; set; }
        public int ExpiredCount { get; set; }
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    }

    public class AuditIssue
    {
        public Guid EntryId { get; set; }
        public string EntryLabel { get; set; } = string.Empty;
        public AuditIssueType Type { get; set; }
        public AuditSeverity Severity { get; set; }
        public string Description { get; set; } = string.Empty;
    }

    public enum AuditIssueType
    {
        WeakPassword,
        ReusedPassword,
        ExpiredEntry,
        NoExpiration
    }

    public enum AuditSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }
}
