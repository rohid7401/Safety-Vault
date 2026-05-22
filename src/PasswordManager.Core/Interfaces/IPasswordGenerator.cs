using PasswordManager.Core.Models;

namespace PasswordManager.Core.Interfaces
{
    public interface IPasswordGenerator
    {
        string Generate(PasswordGeneratorOptions? options = null);
        int CalculateStrength(string password);
    }
}
