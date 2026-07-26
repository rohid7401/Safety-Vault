using System.Security.Cryptography;
using PasswordManager.Core.Exceptions;
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
            var word = options.IncludeWord ?? string.Empty;

            if (options.Length < 4)
                throw new LocalizedArgumentException(AppErrorCode.PasswordLengthTooShort, 4);

            var conflicts = Validate(options);
            if (conflicts.Count > 0)
                throw new GeneratorConstraintException(conflicts);

            var charPool = BuildCharPool(options);

            // ── No word: original behaviour ──
            if (word.Length == 0)
            {
                if (charPool.Length == 0)
                    throw new LocalizedArgumentException(AppErrorCode.NoCharacterSetEnabled);

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

            // ── With an included word: fill the remaining length randomly, embed the word ──
            var fillerLength = options.Length - word.Length; // >= 0 (Validate guarantees it)
            char[] result;
            var attempts = 0;
            do
            {
                var filler = new char[fillerLength];
                for (var i = 0; i < fillerLength; i++)
                    filler[i] = charPool[RandomNumberGenerator.GetInt32(charPool.Length)];

                // Insert the word verbatim at a random position among the filler.
                var pos = RandomNumberGenerator.GetInt32(fillerLength + 1);
                result = new char[options.Length];
                Array.Copy(filler, 0, result, 0, pos);
                word.CopyTo(0, result, pos, word.Length);
                Array.Copy(filler, pos, result, pos + word.Length, fillerLength - pos);
                attempts++;
            }
            // Try to satisfy the required character classes via the filler, but never loop forever:
            // a tight length may leave no room, in which case we accept the best effort.
            while (fillerLength > 0 && !MeetsRequirements(result, options) && attempts < 200);

            return new string(result);
        }

        public IReadOnlyList<GeneratorConflict> Validate(PasswordGeneratorOptions options)
        {
            var conflicts = new List<GeneratorConflict>();
            var word = options.IncludeWord ?? string.Empty;
            if (word.Length == 0)
                return conflicts;

            if (word.Length > options.Length)
                conflicts.Add(GeneratorConflict.WordLongerThanLength);

            if (!string.IsNullOrEmpty(options.ExcludeChars) &&
                word.Any(c => options.ExcludeChars.Contains(c)))
                conflicts.Add(GeneratorConflict.WordContainsExcludedChars);

            var fillerLength = options.Length - word.Length;
            if (fillerLength > 0 && BuildCharPool(options).Length == 0)
                conflicts.Add(GeneratorConflict.NoCharacterSetForFiller);

            return conflicts;
        }

        public void ResolveConflicts(PasswordGeneratorOptions options)
        {
            var word = options.IncludeWord ?? string.Empty;
            if (word.Length == 0)
                return;

            // 1. Grow the length so the word fits.
            if (word.Length > options.Length)
                options.Length = word.Length;

            // 2. Stop excluding characters that the word itself needs.
            if (!string.IsNullOrEmpty(options.ExcludeChars))
                options.ExcludeChars = new string(options.ExcludeChars.Where(c => !word.Contains(c)).ToArray());

            // 3. Make sure there is a character set to fill the remaining length.
            var fillerLength = options.Length - word.Length;
            if (fillerLength > 0 && BuildCharPool(options).Length == 0)
                options.IncludeLowercase = true;
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
