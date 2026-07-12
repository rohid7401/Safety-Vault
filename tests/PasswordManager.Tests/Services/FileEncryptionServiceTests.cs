using System.Text;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Services;
using PasswordManager.Tests.Helpers;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class FileEncryptionServiceTests : IDisposable
    {
        private readonly PgpTestFixture _pgp = new();
        private readonly FileEncryptionService _service = new(new PgpService());

        // ─── Stream round trips ──────────────────────────────────────────────

        [Fact]
        public async Task EncryptThenDecrypt_Stream_RoundTrips()
        {
            var plaintext = Encoding.UTF8.GetBytes("top secret payload — with unicode ñ");

            using var encrypted = new MemoryStream();
            using (var input = new MemoryStream(plaintext))
                await _service.EncryptAsync(input, _pgp.PublicKeyPath, encrypted);

            Assert.NotEqual(plaintext, encrypted.ToArray()); // actually encrypted

            encrypted.Position = 0;
            using var decrypted = new MemoryStream();
            await _service.DecryptAsync(encrypted, _pgp.PrivateKeyPath, PgpTestFixture.Passphrase, decrypted);

            Assert.Equal(plaintext, decrypted.ToArray());
        }

        [Fact]
        public async Task EncryptAsync_EmptyInput_RoundTripsToEmpty()
        {
            using var encrypted = new MemoryStream();
            using (var input = new MemoryStream(Array.Empty<byte>()))
                await _service.EncryptAsync(input, _pgp.PublicKeyPath, encrypted);

            encrypted.Position = 0;
            using var decrypted = new MemoryStream();
            await _service.DecryptAsync(encrypted, _pgp.PrivateKeyPath, PgpTestFixture.Passphrase, decrypted);

            Assert.Empty(decrypted.ToArray());
        }

        [Fact]
        public async Task DecryptAsync_WrongPassphrase_Throws()
        {
            using var encrypted = new MemoryStream();
            using (var input = new MemoryStream(Encoding.UTF8.GetBytes("data")))
                await _service.EncryptAsync(input, _pgp.PublicKeyPath, encrypted);

            encrypted.Position = 0;
            using var output = new MemoryStream();
            await Assert.ThrowsAnyAsync<Exception>(() =>
                _service.DecryptAsync(encrypted, _pgp.PrivateKeyPath, "wrong-passphrase", output));
        }

        // ─── Path convenience ────────────────────────────────────────────────

        [Fact]
        public async Task EncryptFileThenDecryptFile_RoundTrips()
        {
            var srcPath = Path.Combine(_pgp.DataDir, "note.txt");
            var content = "line one\nline two\n";
            await File.WriteAllTextAsync(srcPath, content);

            var encPath = await _service.EncryptFileAsync(srcPath, _pgp.PublicKeyPath);
            Assert.True(File.Exists(encPath));
            Assert.EndsWith(".pgp", encPath);

            var decPath = await _service.DecryptFileAsync(encPath, _pgp.PrivateKeyPath, PgpTestFixture.Passphrase);
            Assert.Equal(content, await File.ReadAllTextAsync(decPath));
        }

        [Fact]
        public async Task EncryptFileAsync_MissingInput_Throws()
        {
            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                _service.EncryptFileAsync(Path.Combine(_pgp.DataDir, "nope.txt"), _pgp.PublicKeyPath));
        }

        // ─── Directory round trip ────────────────────────────────────────────

        [Fact]
        public async Task EncryptDirectoryThenDecrypt_RestoresAllFiles()
        {
            var srcDir = Path.Combine(_pgp.DataDir, "docs");
            Directory.CreateDirectory(Path.Combine(srcDir, "sub"));
            await File.WriteAllTextAsync(Path.Combine(srcDir, "a.txt"), "alpha");
            await File.WriteAllTextAsync(Path.Combine(srcDir, "sub", "b.txt"), "beta");

            var archive = await _service.EncryptDirectoryAsync(srcDir, _pgp.PublicKeyPath);
            Assert.True(File.Exists(archive));

            var outDir = Path.Combine(_pgp.DataDir, "restored");
            await _service.DecryptDirectoryAsync(archive, _pgp.PrivateKeyPath, PgpTestFixture.Passphrase, outDir);

            Assert.Equal("alpha", await File.ReadAllTextAsync(Path.Combine(outDir, "a.txt")));
            Assert.Equal("beta", await File.ReadAllTextAsync(Path.Combine(outDir, "sub", "b.txt")));
        }

        public void Dispose() => _pgp.Dispose();
    }
}
