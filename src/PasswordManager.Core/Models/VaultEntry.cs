using System.Text.Json.Serialization;

namespace PasswordManager.Core.Models
{
    [JsonPolymorphic(TypeDiscriminatorPropertyName = "$type")]
    [JsonDerivedType(typeof(SecureNote), "note")]
    [JsonDerivedType(typeof(CardEntry), "card")]
    [JsonDerivedType(typeof(ServiceEntry), "service")]
    public abstract class VaultEntry
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Label { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = new();

        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
        public DateTime? ExpireTime { get; set; }

        /// <summary>
        /// Pinned to the top of its list. On the base type rather than on each of the three
        /// derived ones, so a starred note, card and password all mean the same thing and cannot
        /// drift apart.
        /// </summary>
        /// <remarks>
        /// A plain bool: vaults written before this existed deserialize it as false, which is
        /// exactly right, so there is no migration and no format version to bump.
        /// </remarks>
        public bool IsFavorite { get; set; }

        // Soft delete
        public bool IsDeleted { get; set; }
        public DateTime? DeletedAt { get; set; }
    }
}
