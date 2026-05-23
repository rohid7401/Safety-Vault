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

        public async Task<string> EncryptFileAsync(string inputPath, string publicKeyPath, string? outputPath = null)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found.", inputPath);
            if (!File.Exists(publicKeyPath))
                throw new FileNotFoundException("Public key not found.", publicKeyPath);

            var size = new FileInfo(inputPath).Length;
            if (size > MaxFileSizeBytes)
                throw new InvalidOperationException(
                    $"File is too large ({FormatBytes(size)}). Maximum supported size is {FormatBytes(MaxFileSizeBytes)}.");

            outputPath ??= inputPath + ".pgp";

            var data = await File.ReadAllBytesAsync(inputPath);
            var encrypted = _pgpService.EncryptBytes(data, publicKeyPath);
            await File.WriteAllBytesAsync(outputPath, encrypted);

            return outputPath;
        }

        public async Task<string> DecryptFileAsync(
            string inputPath, string privateKeyPath, string passphrase, string? outputPath = null)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Input file not found.", inputPath);
            if (!File.Exists(privateKeyPath))
                throw new FileNotFoundException("Private key not found.", privateKeyPath);

            var size = new FileInfo(inputPath).Length;
            if (size > MaxFileSizeBytes)
                throw new InvalidOperationException(
                    $"File is too large ({FormatBytes(size)}). Maximum supported size is {FormatBytes(MaxFileSizeBytes)}.");

            outputPath ??= inputPath.EndsWith(".pgp", StringComparison.OrdinalIgnoreCase)
                ? inputPath[..^4]
                : inputPath + ".decrypted";

            var encrypted = await File.ReadAllBytesAsync(inputPath);
            var data = _pgpService.DecryptBytes(encrypted, privateKeyPath, passphrase);
            await File.WriteAllBytesAsync(outputPath, data);

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
                var data = await File.ReadAllBytesAsync(tempZip);
                var encrypted = _pgpService.EncryptBytes(data, publicKeyPath);
                await File.WriteAllBytesAsync(outputPath, encrypted);
            }
            finally
            {
                if (File.Exists(tempZip))
                    File.Delete(tempZip);
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
                var encrypted = await File.ReadAllBytesAsync(inputPath);
                var data = _pgpService.DecryptBytes(encrypted, privateKeyPath, passphrase);
                await File.WriteAllBytesAsync(tempZip, data);

                ZipFile.ExtractToDirectory(tempZip, extractToPath, overwriteFiles: true);
            }
            finally
            {
                if (File.Exists(tempZip))
                    File.Delete(tempZip);
            }

            return extractToPath;
        }

        // ─── Helpers ─────────────────────────────────────────────────────────

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
