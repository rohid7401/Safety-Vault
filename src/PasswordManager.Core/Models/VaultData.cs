namespace PasswordManager.Core.Models
{
    public class VaultData
    {
        public int Version { get; set; } = VaultData.CurrentVersion;
        public string Algorithm { get; set; } = "AES-GCM-256";
        public List<PasswordEntry> Entries { get; set; } = new();

        public const int CurrentVersion = 2;
    }
}
