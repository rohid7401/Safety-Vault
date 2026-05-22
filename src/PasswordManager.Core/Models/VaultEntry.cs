using System.Text.Json.Serialization;

namespace PasswordManager.Core.Models
{
    [JsonPolymorphic(TypeDiscriminatorPropertyName = "$type")]
    [JsonDerivedType(typeof(PasswordEntry), "password")]
    [JsonDerivedType(typeof(SecureNote), "note")]
    [JsonDerivedType(typeof(CardEntry), "card")]
    public abstract class VaultEntry
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Label { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = new();

        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
        public DateTime? ExpireTime { get; set; }

        // Soft delete
        public bool IsDeleted { get; set; }
        public DateTime? DeletedAt { get; set; }
    }
}
