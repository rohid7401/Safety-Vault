using PasswordManager.Core.Models;
using Xunit;

namespace PasswordManager.Tests.Models
{
    /// <summary>
    /// The address is a sign-in identifier and becomes the PGP key's user ID, which is what a key
    /// server indexes — so a malformed one costs a key nobody can find. These pin the shape the
    /// app accepts, deliberately looser than RFC 5322: anything genuinely deliverable should get
    /// through, and only clearly broken input is turned away.
    /// </summary>
    public class EmailAddressTests
    {
        [Theory]
        [InlineData("juana@ejemplo.com")]
        [InlineData("j@e.co")]
        [InlineData("first.last@sub.domain.org")]
        [InlineData("user+tag@example.com")]
        [InlineData("rd740112@estudiantec.cr")]
        [InlineData("UPPER@EXAMPLE.COM")]
        [InlineData("a_b-c@example.co.uk")]
        public void Accepts(string value) => Assert.True(EmailAddress.IsValid(value));

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("juana")]                 // no @ at all
        [InlineData("@example.com")]          // nothing before the @
        [InlineData("juana@")]                // nothing after it
        [InlineData("a@b@c.com")]             // two @
        [InlineData("juana@example")]         // no dot: legal per RFC, unreachable in practice
        [InlineData("juana@example.")]        // trailing dot leaves an empty label
        [InlineData("juana@.com")]            // leading dot, same
        [InlineData("juana@ex..com")]         // empty label in the middle
        [InlineData("jua na@example.com")]    // space inside
        [InlineData(" juana@example.com")]    // padding: invisible and unrepeatable
        [InlineData("juana@example.com ")]
        public void Rejects(string? value) => Assert.False(EmailAddress.IsValid(value));

        [Fact]
        public void RejectsAnythingLongerThanTheStoredLimit()
        {
            // Would be truncated on save, silently producing an address that is not the one typed.
            var tooLong = new string('a', FieldLimits.Email) + "@example.com";
            Assert.False(EmailAddress.IsValid(tooLong));
        }
    }
}
