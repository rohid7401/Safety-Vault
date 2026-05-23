using PasswordManager.Core.Models;

namespace PasswordManager.App.Services
{
    /// <summary>
    /// Holds the user's password generation preferences app-wide.
    /// Generator page edits these; vault Add/Edit reuses them.
    /// </summary>
    public class GeneratorPreferences
    {
        public PasswordGeneratorOptions Options { get; } = new()
        {
            Length = 20,
            IncludeUppercase = true,
            IncludeLowercase = true,
            IncludeDigits = true,
            IncludeSpecial = true,
            ExcludeChars = string.Empty,
        };

        public event Action? OnChanged;

        public void Notify() => OnChanged?.Invoke();
    }
}
