﻿using System;

namespace PasswordManager.Core.Models
{
    /// Represents a password entry with metadata and flexible fields.
    public class PasswordEntry
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Site { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string EncryptedPassword { get; set; } = string.Empty;
        public string Iv { get; set; } = string.Empty; // Initialization vector for AES encryption

        // Metadata
        public DateTime CreationTime { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdateTime { get; set; } = DateTime.UtcNow;
        public DateTime? ExpireTime { get; set; } // Nullable, set if needed
    }
}
