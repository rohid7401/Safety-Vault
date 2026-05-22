namespace PasswordManager.Core.Interfaces
{
    public interface ITotpService
    {
        string GenerateCode(string base32Secret, DateTime? timestamp = null);
        int GetRemainingSeconds();
        bool ValidateCode(string base32Secret, string code, int tolerance = 1);
    }
}
