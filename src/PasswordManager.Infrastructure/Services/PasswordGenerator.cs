using System.Security.Cryptography;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    public class PasswordGenerator : IPasswordGenerator
    {
        private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
        private const string Digits = "0123456789";
        private const string Special = "!@#$%^&*()-_=+[]{}|;:,.<>?";

        public string Generate(PasswordGeneratorOptions? options = null)
        {
            options ??= new PasswordGeneratorOptions();

            if (options.Length < 4)
                throw new ArgumentException("Password length must be at least 4.");

            var charPool = BuildCharPool(options);
            if (charPool.Length == 0)
                throw new ArgumentException("At least one character set must be enabled.");

            char[] password;
            do
            {
                password = new char[options.Length];
                for (var i = 0; i < options.Length; i++)
                    password[i] = charPool[RandomNumberGenerator.GetInt32(charPool.Length)];
            }
            while (!MeetsRequirements(password, options));

            return new string(password);
        }

        public int CalculateStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;

            var score = 0;
            if (password.Length >= 8) score++;
            if (password.Length >= 12) score++;
            if (password.Length >= 16) score++;
            if (password.Any(char.IsUpper)) score++;
            if (password.Any(char.IsLower)) score++;
            if (password.Any(char.IsDigit)) score++;
            if (password.Any(c => Special.Contains(c))) score++;
            if (password.Length >= 20) score++;

            return Math.Min(score, 8);
        }

        private static string BuildCharPool(PasswordGeneratorOptions options)
        {
            var pool = string.Empty;
            if (options.IncludeUppercase) pool += Uppercase;
            if (options.IncludeLowercase) pool += Lowercase;
            if (options.IncludeDigits) pool += Digits;
            if (options.IncludeSpecial) pool += Special;

            if (!string.IsNullOrEmpty(options.ExcludeChars))
                pool = new string(pool.Where(c => !options.ExcludeChars.Contains(c)).ToArray());

            return pool;
        }

        private static bool MeetsRequirements(char[] password, PasswordGeneratorOptions options)
        {
            if (options.IncludeUppercase && !password.Any(char.IsUpper)) return false;
            if (options.IncludeLowercase && !password.Any(char.IsLower)) return false;
            if (options.IncludeDigits && !password.Any(char.IsDigit)) return false;
            if (options.IncludeSpecial && !password.Any(c => Special.Contains(c))) return false;
            return true;
        }
    }
}
