namespace PasswordManager.Core.Interfaces
{
    public interface ITotpService
    {
        /// <summary>
        /// True if the text is usable as a 2FA secret. Callers use this to reject a bad secret at
        /// the point it is typed: without it the only feedback was an exception the first time
        /// someone tried to read a code, long after they had forgotten what they entered.
        /// </summary>
        bool IsValidSecret(string? base32Secret);

        string GenerateCode(string base32Secret, DateTime? timestamp = null);
        int GetRemainingSeconds();
        bool ValidateCode(string base32Secret, string code, int tolerance = 1);
    }
}
