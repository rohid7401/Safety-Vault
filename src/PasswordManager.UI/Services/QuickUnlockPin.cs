namespace PasswordManager.UI.Services
{
    /// <summary>
    /// What counts as an acceptable PIN.
    ///
    /// <para>One place because two screens ask the question — the enrolment sheet and the unlock
    /// prompt — and a rule that disagreed between them would mean a PIN that can be set but never
    /// entered, discoverable only by burning attempts.</para>
    ///
    /// <para>The rules are deliberately thin. Four digits are safe here for the reason set out in
    /// <c>QuickUnlockSlot</c>: the slot key needs a secret the phone will not export, so an
    /// attacker holding the vault file cannot test even one guess, and an attacker holding the
    /// phone gets five. Guessability rules that would matter for a passphrase are not what stands
    /// between anyone and this vault.</para>
    /// </summary>
    public static class QuickUnlockPin
    {
        public const int MinLength = 4;
        public const int MaxLength = 8;

        /// <summary>Digits only, within length. The field filters as you type; this is the check
        /// that has to hold for a paste, a hardware keyboard, or a value from anywhere else.</summary>
        public static bool IsValid(string? pin) =>
            pin is not null
            && pin.Length >= MinLength
            && pin.Length <= MaxLength
            && pin.All(char.IsAsciiDigit);
    }
}
