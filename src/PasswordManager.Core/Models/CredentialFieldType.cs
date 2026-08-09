namespace PasswordManager.Core.Models
{
    /// <summary>
    /// The kind of value a <see cref="CredentialField"/> holds. Drives the icon, the input
    /// hint, and whether the value is treated as a secret by default. "Pin" is just a secret
    /// made of digits — cryptographically indistinct from a password.
    /// </summary>
    /// <remarks>
    /// ORDER IS PART OF THE STORAGE FORMAT. The vault serializer has no
    /// <c>JsonStringEnumConverter</c>, so these persist as their integer values — <c>Text</c>
    /// is 6 in every vault written so far. Inserting a member anywhere but the end renumbers
    /// the ones after it, which silently retypes fields in vaults already on users' devices
    /// (a stored 6 meaning "Text" would read back as whatever now sits at 6). Append only;
    /// never reorder or remove.
    /// </remarks>
    public enum CredentialFieldType
    {
        Email,
        Username,
        Password,
        Pin,
        Phone,
        TwoFactor,
        Text,

        /// <summary>
        /// A URL. Lets one grouped card hold several sites that share an account but not a
        /// password — a university card whose "Plataforma", "Matrícula" and "Pagos"
        /// credentials each point at their own address.
        /// </summary>
        Web,

        /// <summary>
        /// An API key, access token or recovery key — a secret the service issues rather than one
        /// the user chooses.
        ///
        /// <para>It has its own type because the alternative was storing it as <see cref="Text"/>,
        /// which is not a secret: the value sat unmasked and searchable. Calling it a
        /// <see cref="Password"/> hid it correctly but misdescribed it, and the audit would then
        /// grade something whose strength the user does not control.</para>
        /// </summary>
        Key,
    }
}
