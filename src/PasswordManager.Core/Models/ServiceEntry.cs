namespace PasswordManager.Core.Models
{
    /// <summary>
    /// A service/app card holding one or more <see cref="Credential"/>s. Instead of a fixed
    /// Site/Username/Email/Password shape, each credential is an arbitrary combination of typed
    /// fields, so one card can hold several accounts of the same service (grouped) — or a single
    /// simple login, which stays fast to create.
    /// </summary>
    public class ServiceEntry : VaultEntry
    {
        /// <summary>Service or app name (kept in clear for search).</summary>
        public string Site { get; set; } = string.Empty;

        public List<Credential> Credentials { get; set; } = new();

        /// <summary>
        /// Display preference. When true, the credentials render together in one card; when
        /// false, the list shows each credential as its own card — for users who prefer their
        /// accounts separated even when they share a password.
        /// </summary>
        public bool Grouped { get; set; } = true;
    }
}
