namespace PasswordManager.Core.Models
{
    public class SecureNote : VaultEntry
    {
        public string Title { get; set; } = string.Empty;
        public EncryptedField Content { get; set; } = new();

        /// <summary>
        /// Marks a note the user considers critical, so the index can flag it at a glance.
        ///
        /// <para>A real field rather than a magic tag name: tags are free text, so matching on
        /// one meant guessing at spellings and languages, and a note tagged "Critical" or
        /// "crítica" would silently miss. Absent from notes written before this shipped, where
        /// JSON deserialization leaves it false — which is the right default.</para>
        /// </summary>
        public bool IsCritical { get; set; }
    }
}
