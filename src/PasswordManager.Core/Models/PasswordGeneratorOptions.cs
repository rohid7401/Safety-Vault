namespace PasswordManager.Core.Models
{
    public class PasswordGeneratorOptions
    {
        public int Length { get; set; } = 20;
        public bool IncludeUppercase { get; set; } = true;
        public bool IncludeLowercase { get; set; } = true;
        public bool IncludeDigits { get; set; } = true;
        public bool IncludeSpecial { get; set; } = true;
        public string ExcludeChars { get; set; } = string.Empty;
    }
}
