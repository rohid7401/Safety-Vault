using System.IO.Compression;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Exceptions;

namespace PasswordManager.Infrastructure.Services
{
    public class FileEncryptionService : IFileEncryptionService
    {
        public const long MaxFileSizeBytes = 200L * 1024 * 1024;        // 200 MB
        public const long MaxDirectorySizeBytes = 1024L * 1024 * 1024;  // 1 GB
        // Lower than MaxDirectorySizeBytes: the multi-file bundle path holds every file plus
        // the zip plus the ciphertext in memory at once (mobile has no scratch disk the way
        // the path-based EncryptDirectoryAsync does), so this stays conservative for RAM.
        public const long MaxBundleSizeBytes = 100L * 1024 * 1024;      // 100 MB
        // Caps on the DECOMPRESSED output when extracting an encrypted directory, to defuse
        // decompression bombs (a small zip that expands to hundreds of GB / millions of files).
        private const long MaxExtractedBytes = MaxDirectorySizeBytes;
        private const int MaxExtractedEntries = 100_000;

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

        public async Task EncryptFilesAsync(
            IReadOnlyList<(string Name, byte[] Content)> files, string publicKeyPath, Stream output)
        {
            if (!File.Exists(publicKeyPath))
                throw new FileNotFoundException("Public key not found.", publicKeyPath);
            if (files.Count == 0)
                throw new LocalizedInvalidOperationException(AppErrorCode.NoFilesToBundle);

            var total = files.Sum(f => (long)f.Content.Length);
            if (total > MaxBundleSizeBytes)
                throw new InvalidOperationException(
                    $"Selected files are too large ({FormatBytes(total)}). " +
                    $"Maximum supported size is {FormatBytes(MaxBundleSizeBytes)}.");

            using var zipStream = new MemoryStream();
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create, leaveOpen: true))
            {
                var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var (name, content) in files)
                {
                    var entryName = UniqueEntryName(usedNames, string.IsNullOrWhiteSpace(name) ? "file" : name);
                    using var entryStream = archive.CreateEntry(entryName, CompressionLevel.Optimal).Open();
                    await entryStream.WriteAsync(content);
                }
            }

            zipStream.Position = 0;
            var encrypted = _pgpService.EncryptBytes(zipStream.ToArray(), publicKeyPath);
            await output.WriteAsync(encrypted);
        }

        /// <summary>Two files picked with the same display name would otherwise collide as
        /// zip entries and silently overwrite each other on extraction.</summary>
        private static string UniqueEntryName(HashSet<string> used, string name)
        {
            if (used.Add(name)) return name;

            var ext = Path.GetExtension(name);
            var stem = Path.GetFileNameWithoutExtension(name);
            for (var i = 2; ; i++)
            {
                var candidate = $"{stem} ({i}){ext}";
                if (used.Add(candidate)) return candidate;
            }
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

                SafeExtract(tempZip, extractToPath);
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

        /// <summary>
        /// Extracts a zip while enforcing decompression-bomb limits (total decompressed bytes
        /// and entry count) and rejecting entries whose path escapes the destination (zip-slip).
        /// Replaces <see cref="ZipFile.ExtractToDirectory(string, string)"/>, whose only guard is
        /// against zip-slip and which would happily write an unbounded amount of data.
        /// </summary>
        private static void SafeExtract(string zipPath, string destinationDir) =>
            SafeExtractCore(zipPath, destinationDir, MaxExtractedBytes, MaxExtractedEntries);

        /// <summary>Testable core of <see cref="SafeExtract"/> with injectable limits.</summary>
        internal static void SafeExtractCore(string zipPath, string destinationDir, long maxBytes, int maxEntries)
        {
            // Normalized destination prefix, with a trailing separator, for containment checks.
            var destFull = Path.GetFullPath(destinationDir);
            if (!destFull.EndsWith(Path.DirectorySeparatorChar))
                destFull += Path.DirectorySeparatorChar;

            using var archive = ZipFile.OpenRead(zipPath);

            if (archive.Entries.Count > maxEntries)
                throw new InvalidOperationException(
                    $"Archive has too many entries ({archive.Entries.Count:N0}); " +
                    $"the maximum is {maxEntries:N0} (possible decompression bomb).");

            long totalWritten = 0;
            var chunk = new byte[81920];

            foreach (var entry in archive.Entries)
            {
                var targetPath = Path.GetFullPath(Path.Combine(destinationDir, entry.FullName));

                // Zip-slip guard: the resolved path must stay inside the destination.
                var isDir = targetPath.EndsWith(Path.DirectorySeparatorChar) || entry.Name.Length == 0;
                var containmentCheck = isDir ? targetPath.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar : targetPath;
                if (!containmentCheck.StartsWith(destFull, StringComparison.Ordinal))
                    throw new InvalidOperationException(
                        $"Archive entry '{entry.FullName}' would extract outside the target directory.");

                if (isDir)
                {
                    Directory.CreateDirectory(targetPath);
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);

                using var entryStream = entry.Open();
                using var outFile = File.Create(targetPath);
                int read;
                while ((read = entryStream.Read(chunk, 0, chunk.Length)) > 0)
                {
                    totalWritten += read;
                    if (totalWritten > maxBytes)
                        throw new InvalidOperationException(
                            $"Decompressed contents exceed the maximum of {FormatBytes(maxBytes)} " +
                            "(possible decompression bomb).");
                    outFile.Write(chunk, 0, read);
                }
            }
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
