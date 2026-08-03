namespace PasswordManager.Core.Models
{
    public class AuditReport
    {
        public List<AuditIssue> Issues { get; set; } = new();

        /// <summary>Secrets actually examined — passwords and PINs across every entry.</summary>
        public int TotalPasswords { get; set; }

        /// <summary>
        /// Entries the audit looked at. Reported alongside <see cref="TotalPasswords"/> so the
        /// coverage is visible: a tester could not tell that entries were being skipped, because
        /// the report only ever said how many findings it had, never how much it had read.
        /// </summary>
        public int EntriesScanned { get; set; }

        /// <summary>
        /// Entries holding nothing the audit can judge — no password and no PIN. They are neither
        /// healthy nor unhealthy, and counting them silently as "fine" is how a vault looks clean
        /// while half of it was never checked.
        /// </summary>
        public int EntriesWithoutSecrets { get; set; }

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
