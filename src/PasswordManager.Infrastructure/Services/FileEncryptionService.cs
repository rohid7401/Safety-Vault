using System.IO.Compression;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Infrastructure.Services
{
    public class FileEncryptionService : IFileEncryptionService
    {
        public const long MaxFileSizeBytes = 200L * 1024 * 1024;        // 200 MB
        public const long MaxDirectorySizeBytes = 1024L * 1024 * 1024;  // 1 GB

        private readonly IPgpService _pgpService;

        public FileEncryptionService(IPgpService pgpService)
        {
            _pgpService = pgpService;
        }

        // ─── Stream primitives ────────────────────────────────────────────────

        public Task EncryptAsync(Stream input, string publicKeyPath, Stream output) =>
            EncryptCoreAsync(input, MaxFileSizeBytes, publicKeyPath, output);

        public Task DecryptAsync(Stream input, string privateKeyPath, string passphrase, Stream output) =>
            DecryptCoreAsync(input, MaxFileSizeBytes, privateKeyPath, passphrase, output);

        private async Task EncryptCoreAsync(Stream input, long cap, string publicKeyPath, Stream output)
        {
            if (!File.Exists(publicKeyPath))
                throw new FileNotFoundException("Public key not found.", publicKeyPath);

            var data = await ReadCappedAsync(input, cap);
            var encrypted = _pgpService.EncryptBytes(data, publicKeyPath);
            await output.WriteAsync(encrypted);
        }

        private async Task DecryptCoreAsync(
            Stream input, long cap, string privateKeyPath, string passphrase, Stream output)
        {
            if (!File.Exists(privateKeyPath))
                throw new FileNotFoundException("Private key not found.", privateKeyPath);

            var encrypted = await ReadCappedAsync(input, cap);
            var data = _pgpService.DecryptBytes(encrypted, privateKeyPath, passphrase);
            await output.WriteAsync(data);
        }

        // ─── Path convenience (desktop) ───────────────────────────────────────

        public async Task<string> EncryptFileAsync(string inputPath, string publicKeyPath, string? outputPath = null)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found.", inputPath);

            outputPath ??= inputPath + ".pgp";
            try
            {
                await using var input = File.OpenRead(inputPath);
                await using var output = File.Create(outputPath);
                await EncryptAsync(input, publicKeyPath, output);
            }
            catch
            {
                TryDelete(outputPath);
                throw;
            }
            return outputPath;
        }

        public async Task<string> DecryptFileAsync(
            string inputPath, string privateKeyPath, string passphrase, string? outputPath = null)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found.", inputPath);

            outputPath ??= inputPath.EndsWith(".pgp", StringComparison.OrdinalIgnoreCase)
                ? inputPath[..^4]
                : inputPath + ".decrypted";
            try
            {
                await using var input = File.OpenRead(inputPath);
                await using var output = File.Create(outputPath);
                await DecryptAsync(input, privateKeyPath, passphrase, output);
            }
            catch
            {
                TryDelete(outputPath);
                throw;
            }
            return outputPath;
        }

        public async Task<string> EncryptDirectoryAsync(
            string directoryPath, string publicKeyPath, string? outputPath = null)
        {
            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");

            var totalSize = GetDirectorySize(directoryPath);
            if (totalSize > MaxDirectorySizeBytes)
                throw new InvalidOperationException(
                    $"Directory is too large ({FormatBytes(totalSize)}). " +
                    $"Maximum supported size is {FormatBytes(MaxDirectorySizeBytes)}.");

            outputPath ??= directoryPath.TrimEnd(Path.DirectorySeparatorChar) + ".zip.pgp";

            var tempZip = Path.Combine(Path.GetTempPath(), $"pmgr_{Guid.NewGuid():N}.zip");
            try
            {
                ZipFile.CreateFromDirectory(directoryPath, tempZip, CompressionLevel.Optimal, includeBaseDirectory: false);
                await using var zipInput = File.OpenRead(tempZip);
                await using var output = File.Create(outputPath);
                await EncryptCoreAsync(zipInput, MaxDirectorySizeBytes, publicKeyPath, output);
            }
            catch
            {
                TryDelete(outputPath);
                throw;
            }
            finally
            {
                TryDelete(tempZip);
            }

            return outputPath;
        }

        public async Task<string> DecryptDirectoryAsync(
            string inputPath, string privateKeyPath, string passphrase, string? extractToPath = null)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found.", inputPath);

            extractToPath ??= Path.Combine(
                Path.GetDirectoryName(inputPath) ?? Environment.CurrentDirectory,
                Path.GetFileNameWithoutExtension(Path.GetFileNameWithoutExtension(inputPath)) + "_decrypted");

            Directory.CreateDirectory(extractToPath);

            var tempZip = Path.Combine(Path.GetTempPath(), $"pmgr_{Guid.NewGuid():N}.zip");
            try
            {
                await using (var input = File.OpenRead(inputPath))
                await using (var zipOutput = File.Create(tempZip))
                    await DecryptCoreAsync(input, MaxDirectorySizeBytes, privateKeyPath, passphrase, zipOutput);

                ZipFile.ExtractToDirectory(tempZip, extractToPath, overwriteFiles: true);
            }
            finally
            {
                TryDelete(tempZip);
            }

            return extractToPath;
        }

        // ─── Helpers ─────────────────────────────────────────────────────────

        /// <summary>
        /// Reads a stream fully into memory while enforcing a hard byte cap. Works with
        /// non-seekable streams (e.g. mobile content-URI streams) since it counts as it reads.
        /// </summary>
        private static async Task<byte[]> ReadCappedAsync(Stream input, long maxBytes)
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[81920];
            long total = 0;
            int read;
            while ((read = await input.ReadAsync(chunk)) > 0)
            {
                total += read;
                if (total > maxBytes)
                    throw new InvalidOperationException(
                        $"Input is too large. Maximum supported size is {FormatBytes(maxBytes)}.");
                buffer.Write(chunk, 0, read);
            }
            return buffer.ToArray();
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { /* best effort */ }
        }

        private static long GetDirectorySize(string path)
        {
            try
            {
                return new DirectoryInfo(path)
                    .EnumerateFiles("*", SearchOption.AllDirectories)
                    .Sum(f => f.Length);
            }
            catch
            {
                return 0;
            }
        }

        private static string FormatBytes(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double size = bytes;
            int unit = 0;
            while (size >= 1024 && unit < units.Length - 1)
            {
                size /= 1024;
                unit++;
            }
            return $"{size:0.##} {units[unit]}";
        }
    }
}
