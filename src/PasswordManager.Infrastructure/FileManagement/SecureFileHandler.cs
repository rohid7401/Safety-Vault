using System.Security.Cryptography;

namespace PasswordManager.Infrastructure.FileManagement
{
    public static class SecureFileHandler
    {
        /// <summary>Overwrites file content with random bytes before deletion to hinder recovery.</summary>
        public static void SecureDelete(string path)
        {
            if (!File.Exists(path)) return;
            var length = new FileInfo(path).Length;
            if (length > 0)
                File.WriteAllBytes(path, RandomNumberGenerator.GetBytes((int)length));
            File.Delete(path);
        }
    }
}
