namespace PasswordManager.Core.Models
{
    /// <summary>
    /// Whether a string is usable as an e-mail address here.
    ///
    /// <para>Deliberately not an attempt at RFC 5322 — that grammar admits quoted strings,
    /// comments and bare-IP domains, and every regex people write for it is wrong in one
    /// direction or the other. This checks the shape that actually matters for SafetyVault: the
    /// address is a sign-in identifier and goes into the PGP key's user ID, where a malformed
    /// one makes the key unfindable on a key server. Anything odd but genuinely deliverable is
    /// better accepted than rejected, so the rules stay deliberately loose.</para>
    /// </summary>
    public static class EmailAddress
    {
        public static bool IsValid(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;
            if (value.Any(char.IsWhiteSpace)) return false;
            if (value.Length > FieldLimits.Email) return false;

            var at = value.IndexOf('@');
            // Exactly one '@', with something on each side of it.
            if (at <= 0 || at != value.LastIndexOf('@') || at == value.Length - 1) return false;

            var domain = value[(at + 1)..];

            // A domain needs a dot with real labels around it: "a@b" is syntactically legal in
            // the RFC but is never a real address someone can be reached at.
            var dot = domain.LastIndexOf('.');
            if (dot <= 0 || dot == domain.Length - 1) return false;

            // ".." would make an empty label, and a leading or trailing dot the same.
            if (domain.StartsWith('.') || domain.Contains("..")) return false;

            return true;
        }
    }
}
