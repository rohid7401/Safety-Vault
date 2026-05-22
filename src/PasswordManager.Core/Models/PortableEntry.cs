namespace PasswordManager.Core.Models
{
    public class PortableEntry
    {
        public string Site { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? TotpSecret { get; set; }
        public List<string> Tags { get; set; } = new();
    }
}
