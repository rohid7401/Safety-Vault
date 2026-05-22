using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class PasswordGeneratorTests
    {
        private readonly PasswordGenerator _generator = new();

        [Fact]
        public void Generate_DefaultOptions_ReturnsPasswordWithLength20()
        {
            var password = _generator.Generate();
            Assert.Equal(20, password.Length);
        }

        [Theory]
        [InlineData(8)]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public void Generate_CustomLength_ReturnsCorrectLength(int length)
        {
            var options = new PasswordGeneratorOptions { Length = length };
            var password = _generator.Generate(options);
            Assert.Equal(length, password.Length);
        }

        [Fact]
        public void Generate_AllCharSets_ContainsAllTypes()
        {
            var options = new PasswordGeneratorOptions { Length = 40 };
            var password = _generator.Generate(options);

            Assert.Contains(password, char.IsUpper);
            Assert.Contains(password, char.IsLower);
            Assert.Contains(password, char.IsDigit);
            Assert.Contains(password, c => "!@#$%^&*()-_=+[]{}|;:,.<>?".Contains(c));
        }

        [Fact]
        public void Generate_UppercaseOnly_ContainsOnlyUppercase()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 20,
                IncludeLowercase = false,
                IncludeDigits = false,
                IncludeSpecial = false
            };
            var password = _generator.Generate(options);
            Assert.All(password, c => Assert.True(char.IsUpper(c)));
        }

        [Fact]
        public void Generate_ExcludeChars_DoesNotContainExcluded()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 50,
                ExcludeChars = "aeiouAEIOU0159"
            };
            var password = _generator.Generate(options);
            Assert.All(password, c => Assert.DoesNotContain(c.ToString(), "aeiouAEIOU0159"));
        }

        [Fact]
        public void Generate_LengthTooShort_Throws()
        {
            var options = new PasswordGeneratorOptions { Length = 2 };
            Assert.Throws<ArgumentException>(() => _generator.Generate(options));
        }

        [Fact]
        public void Generate_NoCharSets_Throws()
        {
            var options = new PasswordGeneratorOptions
            {
                IncludeUppercase = false,
                IncludeLowercase = false,
                IncludeDigits = false,
                IncludeSpecial = false
            };
            Assert.Throws<ArgumentException>(() => _generator.Generate(options));
        }

        [Fact]
        public void Generate_TwoCallsProduceDifferentPasswords()
        {
            var p1 = _generator.Generate();
            var p2 = _generator.Generate();
            Assert.NotEqual(p1, p2);
        }

        [Theory]
        [InlineData("", 0)]
        [InlineData("abc", 1)]
        [InlineData("Abc1", 3)]
        [InlineData("Abc1!xyz", 5)]
        [InlineData("Abc1!xyzLongPassword!!", 8)]
        public void CalculateStrength_ReturnsExpectedScore(string password, int expectedMinScore)
        {
            var score = _generator.CalculateStrength(password);
            Assert.InRange(score, expectedMinScore, 8);
        }
    }
}
