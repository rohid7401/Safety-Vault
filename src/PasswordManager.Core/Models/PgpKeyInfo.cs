namespace PasswordManager.Core.Models
{
    public class PgpKeyInfo
    {
        public string FileName { get; set; } = string.Empty;
        public string FullPath { get; set; } = string.Empty;
        public string OwnerLabel { get; set; } = string.Empty;
        public string Fingerprint { get; set; } = string.Empty;
        public DateTime AddedAt { get; set; } = DateTime.UtcNow;
        public bool IsPublic { get; set; } = true;
    }
}
