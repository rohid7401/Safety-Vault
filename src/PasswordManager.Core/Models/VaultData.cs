namespace PasswordManager.Core.Models
{
    public class VaultData
    {
        public int Version { get; set; } = VaultData.CurrentVersion;
        public string Algorithm { get; set; } = "AES-GCM-256";
        public List<VaultEntry> Entries { get; set; } = new();

        /// <summary>
        /// The account's own PGP key pair, armored. Stored inside the vault (protected by
        /// the same Vault Key as everything else) so it travels with the vault to any
        /// device that can unlock it with the passphrase, instead of being a device-local
        /// file that would need separate syncing. Used only for the "encrypt a file for a
        /// contact" feature — never for vault storage encryption itself.
        /// </summary>
        public string? PgpPublicKeyArmored { get; set; }
        public string? PgpPrivateKeyArmored { get; set; }

        /// <summary>
        /// The account's preferences, as name/value pairs.
        ///
        /// <para>Kept here rather than in the device's own preference store so they belong to the
        /// account: two accounts on one phone do not overwrite each other, and the settings travel
        /// in the backup like everything else. Language is the deliberate exception and stays with
        /// the device — it has to work on the sign-in screen, before there is a vault to read.</para>
        ///
        /// <para>Untyped for the same reason the backup's copy is: a build that meets a key it
        /// does not know should ignore it, not fail. Meaning lives in the UI layer, which owns the
        /// defaults.</para>
        /// </summary>
        public Dictionary<string, string> Settings { get; set; } = new();

        // v5 replaces the fixed PasswordEntry with ServiceEntry (flexible multi-credential
        // entries). The old "password" discriminator is no longer registered, so pre-v5 vaults
        // holding PasswordEntry rows must be migrated via plaintext CSV export → import.
        public const int CurrentVersion = 5;
    }
}
