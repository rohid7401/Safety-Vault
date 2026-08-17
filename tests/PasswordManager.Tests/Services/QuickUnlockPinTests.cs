using PasswordManager.UI.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>
    /// The PIN rules are enforced in two places — the enrolment sheet and the unlock prompt — and
    /// the cost of them disagreeing is a PIN that can be set but never entered, discovered only by
    /// spending attempts. These pin the shared rule down so that cannot drift apart again.
    /// </summary>
    public class QuickUnlockPinTests
    {
        [Theory]
        [InlineData("1234")]
        [InlineData("000000")]
        [InlineData("12345678")]
        public void IsValid_AcceptsDigitsWithinLength(string pin) =>
            Assert.True(QuickUnlockPin.IsValid(pin));

        [Theory]
        [InlineData("123")]          // one short
        [InlineData("123456789")]    // one long
        [InlineData("")]
        public void IsValid_RejectsOutOfRangeLengths(string pin) =>
            Assert.False(QuickUnlockPin.IsValid(pin));

        [Theory]
        [InlineData("12a4")]
        [InlineData("12 4")]
        [InlineData("1.234")]
        public void IsValid_RejectsAnythingButDigits(string pin) =>
            Assert.False(QuickUnlockPin.IsValid(pin));

        [Fact]
        public void IsValid_RejectsNonAsciiDigits()
        {
            // char.IsDigit says yes to these; they are not what a numeric keypad produces and not
            // what anyone could retype reliably, so the rule uses IsAsciiDigit.
            Assert.False(QuickUnlockPin.IsValid("١٢٣٤"));
        }

        [Fact]
        public void IsValid_RejectsNull() => Assert.False(QuickUnlockPin.IsValid(null));
    }
}
