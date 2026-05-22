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
        public void GenerateCode_InvalidBase32_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => _totp.GenerateCode("!!!INVALID!!!"));
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
