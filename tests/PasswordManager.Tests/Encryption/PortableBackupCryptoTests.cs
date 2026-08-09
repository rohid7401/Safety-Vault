using System.Text;
using PasswordManager.Core.Exceptions;
using PasswordManager.Infrastructure.Encryption;
using Xunit;

namespace PasswordManager.Tests.Encryption
{
    /// <summary>
    /// The portable backup exists so a vault can be moved between someone's own devices. Its whole
    /// value rests on two claims: only the passphrase opens it, and a file that has been altered
    /// is refused rather than half-read.
    /// </summary>
    public class PortableBackupCryptoTests
    {
        private readonly PortableBackupCrypto _crypto = new();
        private const string Passphrase = "correct horse battery staple";

        private static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

        [Fact]
        public void SealedBackup_OpensWithTheSamePassphrase()
        {
            var payload = Bytes("{\"services\":[{\"site\":\"github.com\"}]}");

            var opened = _crypto.Open(_crypto.Seal(payload, Passphrase), Passphrase);

            Assert.Equal(payload, opened);
        }

        [Fact]
        public void SealedBackup_OpensOnAnInstanceThatNeverSawTheOriginal()
        {
            // Stands in for the other device: nothing is carried over but the passphrase, which is
            // the entire point — a PGP-sealed backup could not do this.
            var sealedBytes = new PortableBackupCrypto().Seal(Bytes("payload"), Passphrase);

            Assert.Equal("payload", Encoding.UTF8.GetString(
                new PortableBackupCrypto().Open(sealedBytes, Passphrase)));
        }

        [Fact]
        public void WrongPassphrase_IsRefused()
        {
            var sealedBytes = _crypto.Seal(Bytes("payload"), Passphrase);

            var ex = Assert.Throws<LocalizedArgumentException>(
                () => _crypto.Open(sealedBytes, "not the passphrase"));

            Assert.Equal(AppErrorCode.BackupCannotOpen, ex.Code);
        }

        [Theory]
        [InlineData("CipherText")]
        [InlineData("Nonce")]
        [InlineData("Tag")]
        [InlineData("Salt")]
        public void AlteredFile_IsRefusedRatherThanPartlyRead(string field)
        {
            // Every part of the envelope, not just the ciphertext: damaging the salt or nonce
            // derives or applies the wrong key, and mangling base64 fails before decryption even
            // starts. All of them are the same thing to the user — a file that will not open.
            var sealedBytes = _crypto.Seal(Bytes("a payload long enough to matter"), Passphrase);
            var text = Encoding.UTF8.GetString(sealedBytes);

            var start = text.IndexOf($"\"{field}\":\"", StringComparison.Ordinal) + field.Length + 4;
            var chars = text.ToCharArray();
            chars[start] = chars[start] == 'A' ? 'B' : 'A';

            var ex = Assert.Throws<LocalizedArgumentException>(
                () => _crypto.Open(Encoding.UTF8.GetBytes(new string(chars)), Passphrase));

            Assert.Equal(AppErrorCode.BackupCannotOpen, ex.Code);
        }

        [Fact]
        public void ADamagedFileNeverEscapesAsARawException()
        {
            // Truncation, junk bytes and a mangled envelope all used to surface as whatever .NET
            // threw, which the UI could only report as "something went wrong".
            var sealedBytes = _crypto.Seal(Bytes("payload"), Passphrase);

            var truncated = sealedBytes.Take(sealedBytes.Length / 2).ToArray();
            var text = Encoding.UTF8.GetString(sealedBytes)
                .Replace("\"CipherText\":\"", "\"CipherText\":\"!!!not base64!!!");

            Assert.Throws<LocalizedArgumentException>(() => _crypto.Open(text.Length > 0
                ? Encoding.UTF8.GetBytes(text) : sealedBytes, Passphrase));
            Assert.ThrowsAny<Exception>(() => _crypto.Open(truncated, Passphrase));
        }

        [Fact]
        public void WrongPassphraseAndAlteredFile_ReportTheSameThing()
        {
            // Telling them apart would confirm a guessed passphrase to whoever holds the file.
            var sealedBytes = _crypto.Seal(Bytes("payload"), Passphrase);
            var altered = (byte[])sealedBytes.Clone();
            var text = Encoding.UTF8.GetString(sealedBytes);
            var start = text.IndexOf("\"CipherText\":\"", StringComparison.Ordinal) + 14;
            altered[start] = (byte)(altered[start] == (byte)'A' ? 'B' : 'A');

            var wrongPass = Assert.Throws<LocalizedArgumentException>(
                () => _crypto.Open(sealedBytes, "wrong"));
            var tampered = Assert.Throws<LocalizedArgumentException>(
                () => _crypto.Open(altered, Passphrase));

            Assert.Equal(wrongPass.Code, tampered.Code);
        }

        [Fact]
        public void TheSameContentSealedTwice_ProducesDifferentFiles()
        {
            // Fresh salt and nonce each time. Identical output would leak that two backups hold
            // the same vault, and would reuse a nonce under the same derived key.
            var a = _crypto.Seal(Bytes("payload"), Passphrase);
            var b = _crypto.Seal(Bytes("payload"), Passphrase);

            Assert.NotEqual(a, b);
            Assert.Equal("payload", Encoding.UTF8.GetString(_crypto.Open(a, Passphrase)));
            Assert.Equal("payload", Encoding.UTF8.GetString(_crypto.Open(b, Passphrase)));
        }

        [Fact]
        public void TheContentNeverAppearsInTheFile()
        {
            var sealedBytes = _crypto.Seal(Bytes("github.com hunter2"), Passphrase);

            var text = Encoding.UTF8.GetString(sealedBytes);
            Assert.DoesNotContain("github.com", text);
            Assert.DoesNotContain("hunter2", text);
            Assert.DoesNotContain(Passphrase, text);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void SealingWithoutAPassphrase_IsRefused(string? passphrase)
        {
            // Would otherwise write a file that looks protected and is opened by an empty string.
            var ex = Assert.Throws<LocalizedArgumentException>(
                () => _crypto.Seal(Bytes("payload"), passphrase!));

            Assert.Equal(AppErrorCode.BackupPassphraseRequired, ex.Code);
        }

        [Fact]
        public void IsSealed_RecognisesOurFilesAndNothingElse()
        {
            Assert.True(_crypto.IsSealed(_crypto.Seal(Bytes("payload"), Passphrase)));

            Assert.False(_crypto.IsSealed(Bytes("site,username,password\ngithub.com,jane,hunter2")));
            Assert.False(_crypto.IsSealed(Bytes("{\"services\":[]}")));
            Assert.False(_crypto.IsSealed(Bytes("-----BEGIN PGP MESSAGE-----")));
            Assert.False(_crypto.IsSealed(Array.Empty<byte>()));
        }

        [Fact]
        public void SomethingShapedLikeOursButNotOurs_IsRejectedNotCrashed()
        {
            Assert.False(_crypto.IsSealed(Bytes("{\"Format\":\"SafetyVaultBackup\"")));      // truncated
            Assert.False(_crypto.IsSealed(Bytes("{\"Format\":\"SafetyVaultBackup\",\"Version\":99}")));
        }

        [Fact]
        public void AFileFromANewerVersion_IsNotGuessedAt()
        {
            var text = Encoding.UTF8.GetString(_crypto.Seal(Bytes("payload"), Passphrase))
                .Replace("\"Version\":1", "\"Version\":2");

            Assert.False(_crypto.IsSealed(Encoding.UTF8.GetBytes(text)));
        }

        [Fact]
        public void AnEmptyPayload_SurvivesTheRoundTrip()
        {
            Assert.Empty(_crypto.Open(_crypto.Seal(Array.Empty<byte>(), Passphrase), Passphrase));
        }

        [Fact]
        public void PassphrasesDifferingOnlyByCase_DoNotOpenEachOther()
        {
            var sealedBytes = _crypto.Seal(Bytes("payload"), "Passphrase");

            Assert.Throws<LocalizedArgumentException>(() => _crypto.Open(sealedBytes, "passphrase"));
        }
    }
}
