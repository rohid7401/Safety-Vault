using System.IO.Compression;
using System.Text;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>
    /// N3 — decompression-bomb / zip-slip protection in the directory-decrypt path.
    /// Exercises <see cref="FileEncryptionService.SafeExtractCore"/> directly with small
    /// limits (the production caps are 1 GB / 100k entries, impractical to hit in a test).
    /// </summary>
    public class SafeExtractTests : IDisposable
    {
        private readonly string _dir =
            Path.Combine(Path.GetTempPath(), "pmgr_test_" + Guid.NewGuid().ToString("N"));

        public SafeExtractTests() => Directory.CreateDirectory(_dir);

        private string MakeZip(Action<ZipArchive> build)
        {
            var zipPath = Path.Combine(_dir, "in.zip");
            using var fs = File.Create(zipPath);
            using var archive = new ZipArchive(fs, ZipArchiveMode.Create);
            build(archive);
            return zipPath;
        }

        private static void AddEntry(ZipArchive archive, string name, byte[] content)
        {
            var entry = archive.CreateEntry(name);
            using var s = entry.Open();
            s.Write(content, 0, content.Length);
        }

        [Fact]
        public void SafeExtractCore_NormalZip_ExtractsAllFiles()
        {
            var zip = MakeZip(a =>
            {
                AddEntry(a, "a.txt", Encoding.UTF8.GetBytes("hello"));
                AddEntry(a, "sub/b.txt", Encoding.UTF8.GetBytes("world"));
            });
            var dest = Path.Combine(_dir, "out");

            FileEncryptionService.SafeExtractCore(zip, dest, maxBytes: 1024, maxEntries: 100);

            Assert.Equal("hello", File.ReadAllText(Path.Combine(dest, "a.txt")));
            Assert.Equal("world", File.ReadAllText(Path.Combine(dest, "sub", "b.txt")));
        }

        [Fact]
        public void SafeExtractCore_DecompressedBytesOverCap_Throws()
        {
            // 2 KB of highly-compressible zeros; the zip on disk is tiny but decompresses past the cap.
            var zip = MakeZip(a => AddEntry(a, "big.bin", new byte[2048]));
            var dest = Path.Combine(_dir, "out");

            var ex = Assert.Throws<InvalidOperationException>(
                () => FileEncryptionService.SafeExtractCore(zip, dest, maxBytes: 1024, maxEntries: 100));
            Assert.Contains("decompression bomb", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void SafeExtractCore_TooManyEntries_Throws()
        {
            var zip = MakeZip(a =>
            {
                for (int i = 0; i < 5; i++)
                    AddEntry(a, $"f{i}.txt", Encoding.UTF8.GetBytes("x"));
            });
            var dest = Path.Combine(_dir, "out");

            var ex = Assert.Throws<InvalidOperationException>(
                () => FileEncryptionService.SafeExtractCore(zip, dest, maxBytes: 1_000_000, maxEntries: 3));
            Assert.Contains("too many entries", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void SafeExtractCore_ZipSlipEntry_Throws()
        {
            // Entry name tries to escape the destination directory.
            var zip = MakeZip(a => AddEntry(a, "../escaped.txt", Encoding.UTF8.GetBytes("evil")));
            var dest = Path.Combine(_dir, "out");

            var ex = Assert.Throws<InvalidOperationException>(
                () => FileEncryptionService.SafeExtractCore(zip, dest, maxBytes: 1_000_000, maxEntries: 100));
            Assert.Contains("outside the target directory", ex.Message, StringComparison.OrdinalIgnoreCase);

            Assert.False(File.Exists(Path.Combine(_dir, "escaped.txt")));
        }

        public void Dispose()
        {
            try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
        }
    }
}
