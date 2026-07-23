namespace PasswordManager.Core.Models
{
    /// <summary>
    /// The kind of value a <see cref="CredentialField"/> holds. Drives the icon, the input
    /// hint, and whether the value is treated as a secret by default. "Pin" is just a secret
    /// made of digits — cryptographically indistinct from a password.
    /// </summary>
    public enum CredentialFieldType
    {
        Email,
        Username,
        Password,
        Pin,
        Phone,
        TwoFactor,
        Text,
    }
}
