namespace PasswordManager.Core.Models
{
    public class CardEntry : VaultEntry
    {
        public string CardholderName { get; set; } = string.Empty;
        public EncryptedField CardNumber { get; set; } = new();
        public EncryptedField Cvv { get; set; } = new();
        public int ExpiryMonth { get; set; }
        public int ExpiryYear { get; set; }

        /// <summary>
        /// The cash-machine PIN, encrypted like the other secrets. Optional and null when unset —
        /// not every card has one worth storing, and an empty <see cref="EncryptedField"/> would
        /// be indistinguishable from a PIN that decrypts to nothing.
        /// </summary>
        public EncryptedField? Pin { get; set; }

        /// <summary>
        /// The bank account this card belongs to, as the id of a <see cref="ServiceEntry"/> in the
        /// same vault. Cards and the login that administers them are the same thing to the person
        /// holding them, and several cards commonly share one account.
        ///
        /// <para>A plain id rather than a reference: entries are stored as a flat list and the
        /// target may be deleted, renamed or restored from the trash independently. Anything
        /// reading this must cope with it pointing nowhere.</para>
        /// </summary>
        public Guid? LinkedEntryId { get; set; }
    }
}
