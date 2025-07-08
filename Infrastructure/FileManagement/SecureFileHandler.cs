using System.IO;
using System.Security.Cryptography;

namespace PasswordManager.Infrastructure.FileManagement
{
    /// <summary>
    /// Provides methods for secure file operations.
    /// </summary>
    public static class SecureFileHandler
    {
        /// <summary>
        /// Securely deletes a file by first overwriting its content with random data.
        /// </summary>
        /// <param name="path">The path of the file to delete.</param>
        public static void SecureDelete(string path)
        {
            if (File.Exists(path))
            {
                // Overwrite with random data to prevent recovery
                var fileInfo = new FileInfo(path);
                byte[] randomData = RandomNumberGenerator.GetBytes((int)fileInfo.Length);
                File.WriteAllBytes(path, randomData);
                File.Delete(path);
            }
        }
    }
}
