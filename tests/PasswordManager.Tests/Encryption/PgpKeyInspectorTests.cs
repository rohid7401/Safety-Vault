using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Tests.Helpers;
using Xunit;

namespace PasswordManager.Tests.Encryption
{
    /// <summary>
    /// N8 — inspecting a public key before trusting it (real fingerprint + user IDs, and
    /// checking whether an expected email is actually present among the identities).
    /// </summary>
    public class PgpKeyInspectorTests : IDisposable
    {
        private readonly PgpTestFixture _pgp = new(); // generates a key with UID "test@test.local"

        [Fact]
        public async Task InspectPublicKey_ReturnsRealFingerprintAndUserIds()
        {
            var armored = await File.ReadAllTextAsync(_pgp.PublicKeyPath);
            var details = new PgpService().InspectPublicKey(armored);

            // A v4 RSA key fingerprint is 20 bytes → 40 hex chars.
            Assert.Equal(40, details.Fingerprint.Length);
            Assert.Matches("^[0-9A-F]+$", details.Fingerprint);
            Assert.Contains(details.UserIds, uid => uid.Contains("test@test.local"));
        }

        [Fact]
        public async Task HasUserIdFor_MatchesTheKeysEmail_AndRejectsOthers()
        {
            var armored = await File.ReadAllTextAsync(_pgp.PublicKeyPath);
            var details = new PgpService().InspectPublicKey(armored);

            Assert.True(details.HasUserIdFor("test@test.local"));
            Assert.False(details.HasUserIdFor("attacker@evil.example"));
        }

        [Fact]
        public void InspectPublicKey_GarbageInput_Throws()
        {
            Assert.ThrowsAny<Exception>(() => new PgpService().InspectPublicKey("not a real key"));
        }

        public void Dispose() => _pgp.Dispose();
    }
}
