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

    /// <summary>
    /// One finding of the audit. Carries only structured data — never a display string:
    /// the auditor lives in Infrastructure and has no access to the UI's translations,
    /// so the wording is built in the UI layer from <see cref="Type"/> plus whichever
    /// of the detail fields below applies to it.
    /// </summary>
    public class AuditIssue
    {
        public Guid EntryId { get; set; }
        public string EntryLabel { get; set; } = string.Empty;
        public AuditIssueType Type { get; set; }
        public AuditSeverity Severity { get; set; }

        /// <summary>Strength score 0–8 of the offending password (<see cref="AuditIssueType.WeakPassword"/>).</summary>
        public int Strength { get; set; }

        /// <summary>How many *other* entries share this same password (<see cref="AuditIssueType.ReusedPassword"/>).</summary>
        public int SharedWith { get; set; }

        /// <summary>When the secret expired (<see cref="AuditIssueType.ExpiredEntry"/>).</summary>
        public DateTime? ExpiredOn { get; set; }
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
