using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordManager.Core.Models
{
    public class Credential
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string EncryptedPassword { get; set; } = string.Empty;
        public string? Label { get; set; }

        // Metadata
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
        public DateTime? ExpireTime { get; set; }
    }
}
