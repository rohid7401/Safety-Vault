using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    public class KeyDirectoryService : IKeyDirectoryService
    {
        private const string KeyDirectoryName = "key_directory";

        public string GetKeyDirectoryPath(string vaultPath) =>
            Path.Combine(vaultPath, KeyDirectoryName);

        public Task<List<PgpKeyInfo>> ListKeysAsync(string vaultPath)
        {
            var dir = GetKeyDirectoryPath(vaultPath);
            if (!Directory.Exists(dir))
                return Task.FromResult(new List<PgpKeyInfo>());

            var keys = Directory.GetFiles(dir, "*.asc")
                .Select(f =>
                {
                    var fi = new FileInfo(f);
                    var label = Path.GetFileNameWithoutExtension(f).Replace('_', ' ');
                    return new PgpKeyInfo
                    {
                        FileName = fi.Name,
                        FullPath = fi.FullName,
                        OwnerLabel = label,
                        AddedAt = fi.CreationTimeUtc,
                        Fingerprint = ComputeShortFingerprint(fi.FullName),
                        IsPublic = true,
                    };
                })
                .OrderBy(k => k.OwnerLabel)
                .ToList();

            return Task.FromResult(keys);
        }

        public async Task<PgpKeyInfo> ImportKeyAsync(string vaultPath, string sourceKeyPath, string ownerLabel)
        {
            if (!File.Exists(sourceKeyPath))
                throw new FileNotFoundException("Source key not found.", sourceKeyPath);

            var dir = GetKeyDirectoryPath(vaultPath);
            Directory.CreateDirectory(dir);

            var safeName = SanitizeLabel(ownerLabel);
            var dest = Path.Combine(dir, $"{safeName}.asc");

            // Avoid overwriting; suffix with timestamp if collision
            if (File.Exists(dest))
                dest = Path.Combine(dir, $"{safeName}_{DateTime.UtcNow:yyyyMMddHHmmss}.asc");

            var bytes = await File.ReadAllBytesAsync(sourceKeyPath);
            await File.WriteAllBytesAsync(dest, bytes);

            return new PgpKeyInfo
            {
                FileName = Path.GetFileName(dest),
                FullPath = dest,
                OwnerLabel = ownerLabel,
                AddedAt = DateTime.UtcNow,
                Fingerprint = ComputeShortFingerprint(dest),
                IsPublic = true,
            };
        }

        public Task RemoveKeyAsync(string vaultPath, string fileName)
        {
            var dir = GetKeyDirectoryPath(vaultPath);
            var path = Path.Combine(dir, fileName);
            if (File.Exists(path))
                File.Delete(path);
            return Task.CompletedTask;
        }

        public async Task<PgpKeyInfo> PublishOwnKeyAsync(string vaultPath, string ownPublicKeyPath, string ownerLabel)
        {
            return await ImportKeyAsync(vaultPath, ownPublicKeyPath, ownerLabel);
        }

        private static string SanitizeLabel(string label)
        {
            var invalid = Path.GetInvalidFileNameChars();
            var clean = string.Concat(label.Select(c => invalid.Contains(c) || c == ' ' ? '_' : c));
            return string.IsNullOrEmpty(clean) ? "key" : clean;
        }

        private static string ComputeShortFingerprint(string path)
        {
            try
            {
                using var stream = File.OpenRead(path);
                using var sha = System.Security.Cryptography.SHA256.Create();
                var hash = sha.ComputeHash(stream);
                return Convert.ToHexString(hash, 0, 8);
            }
            catch
            {
                return "unknown";
            }
        }
    }
}
