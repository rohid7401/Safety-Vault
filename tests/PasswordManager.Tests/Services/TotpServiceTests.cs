using PasswordManager.Core.Exceptions;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class TotpServiceTests
    {
        private readonly TotpService _totp = new();

        // RFC 6238 test vector: secret = "12345678901234567890" (Base32: GEZDGNBVGY3TQOJQ...)
        private const string TestSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        [Fact]
        public void GenerateCode_ReturnsExactly6Digits()
        {
            var code = _totp.GenerateCode(TestSecret);
            Assert.Equal(6, code.Length);
            Assert.All(code, c => Assert.True(char.IsDigit(c)));
        }

        [Fact]
        public void GenerateCode_SameTimestamp_ReturnsSameCode()
        {
            var timestamp = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var code1 = _totp.GenerateCode(TestSecret, timestamp);
            var code2 = _totp.GenerateCode(TestSecret, timestamp);
            Assert.Equal(code1, code2);
        }

        [Fact]
        public void GenerateCode_DifferentTimesteps_ReturnsDifferentCodes()
        {
            var t1 = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var t2 = new DateTime(2024, 1, 1, 0, 1, 0, DateTimeKind.Utc);
            var code1 = _totp.GenerateCode(TestSecret, t1);
            var code2 = _totp.GenerateCode(TestSecret, t2);
            Assert.NotEqual(code1, code2);
        }

        [Fact]
        public void ValidateCode_CurrentCode_ReturnsTrue()
        {
            var code = _totp.GenerateCode(TestSecret);
            Assert.True(_totp.ValidateCode(TestSecret, code));
        }

        [Fact]
        public void ValidateCode_WrongCode_ReturnsFalse()
        {
            Assert.False(_totp.ValidateCode(TestSecret, "000000"));
        }

        [Fact]
        public void ValidateCode_WithTolerance_AcceptsAdjacentSteps()
        {
            var now = DateTime.UtcNow;
            var thirtySecsAgo = now.AddSeconds(-30);
            var codeFromPast = _totp.GenerateCode(TestSecret, thirtySecsAgo);
            Assert.True(_totp.ValidateCode(TestSecret, codeFromPast, tolerance: 1));
        }

        [Fact]
        public void GetRemainingSeconds_ReturnsBetween1And30()
        {
            var remaining = _totp.GetRemainingSeconds();
            Assert.InRange(remaining, 1, 30);
        }

        [Fact]
        public void GenerateCode_InvalidBase32_ThrowsTranslatableError()
        {
            // Was a FormatException naming the offending character in English, which reached the
            // user as the generic "something went wrong".
            var ex = Assert.Throws<LocalizedArgumentException>(() => _totp.GenerateCode("!!!INVALID!!!"));
            Assert.Equal(AppErrorCode.InvalidTotpSecret, ex.Code);
        }

        [Theory]
        // Base32 has no 0, 1, 8 or 9, so a secret someone typed as plain digits is rejected —
        // exactly what a tester hit after entering random numbers.
        [InlineData("10948320")]
        [InlineData("000000")]
        [InlineData("!!!INVALID!!!")]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData(null)]
        public void IsValidSecret_RejectsWhatCannotProduceCodes(string? secret)
        {
            Assert.False(_totp.IsValidSecret(secret));
        }

        [Theory]
        [InlineData("JBSWY3DPEHPK3PXP")]
        [InlineData("jbswy3dpehpk3pxp")]      // case-insensitive
        [InlineData("JBSW Y3DP EHPK 3PXP")]   // grouped the way sites display it
        [InlineData("JBSWY3DPEHPK3PXP====")]  // padded
        [InlineData("hola")]                   // letters only: valid Base32, so it really does work
        public void IsValidSecret_AcceptsRealSecrets(string secret)
        {
            Assert.True(_totp.IsValidSecret(secret));
        }

        [Fact]
        public void GenerateCode_SecretTooShortToFormAByte_ThrowsRatherThanReturningANumber()
        {
            // "A" is a legal character but decodes to nothing, leaving no key. Signing with an
            // empty key would return a confident six digits that could never match.
            var ex = Assert.Throws<LocalizedArgumentException>(() => _totp.GenerateCode("A"));
            Assert.Equal(AppErrorCode.InvalidTotpSecret, ex.Code);
        }

        [Fact]
        public void GenerateCode_Base32WithSpacesAndPadding_Works()
        {
            var code1 = _totp.GenerateCode(TestSecret);
            var code2 = _totp.GenerateCode("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ====");
            Assert.Equal(code1, code2);
        }

        [Fact]
        public void GenerateCode_KnownVector_ProducesExpectedCode()
        {
            // RFC 6238 test: SHA1, secret "12345678901234567890", time = 59 (Unix)
            var timestamp = DateTimeOffset.FromUnixTimeSeconds(59).UtcDateTime;
            var code = _totp.GenerateCode(TestSecret, timestamp);
            Assert.Equal("287082", code);
        }
    }
}
