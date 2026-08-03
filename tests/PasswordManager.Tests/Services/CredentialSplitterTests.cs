using PasswordManager.Core.Models;
using PasswordManager.UI.Services;
using Xunit;
using T = PasswordManager.Core.Models.CredentialFieldType;

namespace PasswordManager.Tests.Services
{
    /// <summary>
    /// The splitter rearranges what someone typed, so a wrong guess quietly files a password under
    /// the wrong login. These pin the rule: an account is complete once it has a password, and the
    /// next password — or the next identifier after it — begins another one.
    /// </summary>
    public class CredentialSplitterTests
    {
        private static int[] Assign(params T[] fields) =>
            CredentialSplitter.AssignAccounts(fields).ToArray();

        [Fact]
        public void TwoLoginsTypedInOrder_SplitAtTheSecondIdentity()
        {
            // The shape a tester actually produced: e-mail, password, e-mail, password.
            Assert.Equal(new[] { 0, 0, 1, 1 }, Assign(T.Email, T.Password, T.Email, T.Password));
        }

        [Fact]
        public void ASingleLogin_IsLeftAlone()
        {
            Assert.Equal(new[] { 0, 0 }, Assign(T.Email, T.Password));
            Assert.Equal(new[] { 0, 0, 0 }, Assign(T.Username, T.Password, T.Pin));
        }

        [Fact]
        public void TwoPasswordsBackToBack_StillBecomeTwoAccounts()
        {
            Assert.Equal(new[] { 0, 1 }, Assign(T.Password, T.Password));
        }

        [Fact]
        public void IdentifiersBeforeThePassword_StayWithIt()
        {
            // An account can legitimately carry both a username and an e-mail; nothing has been
            // completed until a password shows up, so these must not be torn apart.
            Assert.Equal(new[] { 0, 0, 0 }, Assign(T.Email, T.Username, T.Password));
        }

        [Fact]
        public void ExtrasAfterThePassword_StayWithTheAccountTheyFollow()
        {
            // A PIN, a 2FA secret or a note belongs to the login above it, not to a new one.
            Assert.Equal(new[] { 0, 0, 0, 0 }, Assign(T.Email, T.Password, T.Pin, T.Text));
            Assert.Equal(new[] { 0, 0, 0, 1, 1 },
                Assign(T.Email, T.Password, T.TwoFactor, T.Email, T.Password));
        }

        [Fact]
        public void ThreeLogins_BecomeThree()
        {
            Assert.Equal(new[] { 0, 0, 1, 1, 2, 2 },
                Assign(T.Email, T.Password, T.Email, T.Password, T.Username, T.Password));
        }

        [Fact]
        public void NoPasswordAtAll_IsNeverSplit()
        {
            // Without a password nothing is complete, so two e-mails are two ways to reach the
            // same account rather than two accounts.
            Assert.Equal(new[] { 0, 0, 0 }, Assign(T.Email, T.Username, T.Phone));
        }

        [Fact]
        public void EveryFieldIsAccountedFor_AndOrderIsPreserved()
        {
            var fields = new[] { T.Email, T.Password, T.Text, T.Username, T.Password };

            var assignment = CredentialSplitter.AssignAccounts(fields);

            Assert.Equal(fields.Length, assignment.Count);          // nothing dropped
            Assert.Equal(0, assignment[0]);                          // starts at the first account
            for (var i = 1; i < assignment.Count; i++)
                Assert.InRange(assignment[i] - assignment[i - 1], 0, 1); // never skips or goes back
        }

        [Fact]
        public void NoFields_ProducesNothing()
        {
            Assert.Empty(CredentialSplitter.AssignAccounts(Array.Empty<T>()));
        }
    }
}
