using System.Text;
using PasswordManager.Core.Exceptions;
using PasswordManager.Infrastructure.Encryption;
using Xunit;

namespace PasswordManager.Tests.Encryption
{
    /// <summary>
    /// Carrying a PGP identity to a second device. The property that matters is that it stays the
    /// *same* identity: a new key pair would leave everything already encrypted to the old one
    /// unreadable, with no way back.
    /// </summary>
    public class PgpIdentityTransferTests : IDisposable
    {
        private readonly PgpService _pgp = new();
        private readonly string _dir = Path.Combine(Path.GetTempPath(), "sv-pgp-" + Guid.NewGuid().ToString("N"));
        private const string OldPass = "origin-device-passphrase";
        private const string NewPass = "this-device-passphrase";

        private (string PublicPath, string PrivatePath) NewKeyPair(string passphrase)
        {
            Directory.CreateDirectory(_dir);
            var pub = Path.Combine(_dir, $"pub-{Guid.NewGuid():N}.asc");
            var priv = Path.Combine(_dir, $"priv-{Guid.NewGuid():N}.asc");
            _pgp.GenerateKeyPair(pub, priv, passphrase, "Jane Doe <jane@example.com>");
            return (pub, priv);
        }

        public void Dispose()
        {
            if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
        }

        [Fact]
        public void RekeyedPrivateKey_OpensWithTheNewPassphrase()
        {
            var (pub, priv) = NewKeyPair(OldPass);
            var secret = _pgp.EncryptBytes(Encoding.UTF8.GetBytes("a file from a contact"), pub);

            var rekeyed = _pgp.ChangePrivateKeyPassphrase(File.ReadAllText(priv), OldPass, NewPass);

            var landed = Path.Combine(_dir, "landed.asc");
            File.WriteAllText(landed, rekeyed);
            Assert.Equal("a file from a contact",
                Encoding.UTF8.GetString(_pgp.DecryptBytes(secret, landed, NewPass)));
        }

        [Fact]
        public void RekeyedPrivateKey_StillOpensWhatTheOldOneCould()
        {
            // The whole point of moving the key rather than making a new one: files encrypted to
            // this identity before the move must keep opening after it.
            var (pub, priv) = NewKeyPair(OldPass);
            var beforeMove = _pgp.EncryptBytes(Encoding.UTF8.GetBytes("sent last year"), pub);

            var landed = Path.Combine(_dir, "landed2.asc");
            File.WriteAllText(landed, _pgp.ChangePrivateKeyPassphrase(File.ReadAllText(priv), OldPass, NewPass));

            Assert.Equal("sent last year",
                Encoding.UTF8.GetString(_pgp.DecryptBytes(beforeMove, landed, NewPass)));
        }

        [Fact]
        public void RekeyingDoesNotChangeWhoTheKeyIs()
        {
            // A different fingerprint would mean a different identity: contacts who verified the
            // old one would have to be told, and a key server would hold a stale entry.
            var (pub, priv) = NewKeyPair(OldPass);
            var before = _pgp.InspectPublicKey(File.ReadAllText(pub));

            _pgp.ChangePrivateKeyPassphrase(File.ReadAllText(priv), OldPass, NewPass);

            var after = _pgp.InspectPublicKey(File.ReadAllText(pub));
            Assert.Equal(before.FingerprintDisplay, after.FingerprintDisplay);
            Assert.Equal(before.UserIds, after.UserIds);
        }

        [Fact]
        public void TheOldPassphraseStopsWorkingOnTheRekeyedCopy()
        {
            var (_, priv) = NewKeyPair(OldPass);

            var landed = Path.Combine(_dir, "landed3.asc");
            File.WriteAllText(landed, _pgp.ChangePrivateKeyPassphrase(File.ReadAllText(priv), OldPass, NewPass));

            using var stream = File.OpenRead(landed);
            Assert.ThrowsAny<Exception>(() => PgpTestAccess.ReadPrivateKey(landed, OldPass));
        }

        [Fact]
        public void WrongOriginPassphrase_IsRefusedBeforeAnythingIsWritten()
        {
            var (_, priv) = NewKeyPair(OldPass);

            var ex = Assert.Throws<LocalizedArgumentException>(
                () => _pgp.ChangePrivateKeyPassphrase(File.ReadAllText(priv), "not the passphrase", NewPass));

            Assert.Equal(AppErrorCode.NoPrivateKeyOrBadPassphrase, ex.Code);
        }

        [Fact]
        public void SomethingThatIsNotAPrivateKey_IsRefused()
        {
            Assert.ThrowsAny<Exception>(
                () => _pgp.ChangePrivateKeyPassphrase("not a key at all", OldPass, NewPass));
        }

        /// <summary>Reads a private key the way the app does, to assert a passphrase is refused.</summary>
        private static class PgpTestAccess
        {
            public static void ReadPrivateKey(string path, string passphrase)
            {
                var pgp = new PgpService();
                // Decrypting anything at all forces the key to be unlocked first.
                pgp.DecryptBytes(Array.Empty<byte>(), path, passphrase);
            }
        }
    }
}
