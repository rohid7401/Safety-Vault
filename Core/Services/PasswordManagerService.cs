using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;
using System.IO;
using System.Threading.Tasks;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.FileManagement;
using PasswordManager.Core.Interfaces;
using PasswordManager.Infrastructure.Encryption;

namespace PasswordManager.Core.Services
{
    public class PasswordManagerService
    {
        // Handles JSON file operations and PGP encryption/decryption
        private readonly JsonFileHandler<PasswordEntry> _jsonHandler;
        private readonly IPgpService _pgpService;
        private readonly IAesService _aesService;
        private readonly string _pgpPublicKeyPath;
        private readonly string _pgpPrivateKeyPath;
        private readonly string _pgpPassphrase;
        private readonly string _dataFolderPath;

        private string? _aesKey; // This will be loaded securely

        private const string VaultFileName = "vault.data.pgp";
        private const string AesKeyFileName = "vault.key.pgp";

        // Constructor is now private to enforce async initialization
        private PasswordManagerService(
            string dataFolderPath,
            string pgpPublicKeyPath,
            string pgpPrivateKeyPath,
            string pgpPassphrase,
            IPgpService pgpService,
            IAesService aesService)
        {
            _jsonHandler = new JsonFileHandler<PasswordEntry>();
            _dataFolderPath = dataFolderPath;
            _pgpService = pgpService;
            _aesService = aesService;
            _pgpPublicKeyPath = pgpPublicKeyPath;
            _pgpPrivateKeyPath = pgpPrivateKeyPath;
            _pgpPassphrase = pgpPassphrase;
        }


        public static async Task<PasswordManagerService> CreateAsync(
            string dataFolderPath,
            string? pgpPublicKeyPath,
            string? pgpPrivateKeyPath,
            string pgpPassphrase)
        {
            // Validate paths and passphrase before creating the service
            if (string.IsNullOrEmpty(pgpPublicKeyPath))
            {
                pgpPublicKeyPath = Path.Combine(dataFolderPath, "public_key.asc");
                if (!File.Exists(pgpPublicKeyPath))
                {
                    throw new FileNotFoundException("Public key file not found in the default location. Please provide a valid path.");
                }
            }
            ValidatePublicKeyFile(pgpPublicKeyPath);

            if (string.IsNullOrEmpty(pgpPrivateKeyPath))
            {
                pgpPrivateKeyPath = Path.Combine(dataFolderPath, "private_key.asc");
                if (!File.Exists(pgpPrivateKeyPath))
                {
                    throw new FileNotFoundException("Private key file not found in the default location. Please provide a valid path.");
                }
            }
            // We validate the private key and passphrase during AES key decryption/creation.

            if (string.IsNullOrEmpty(pgpPassphrase))
            {
                throw new ArgumentException("PGP passphrase (Master Key) cannot be empty.");
            }

            // Create concrete instances of the services to be injected.
            var pgpService = new PgpService();
            var aesService = new AesService();

            var service = new PasswordManagerService(dataFolderPath, pgpPublicKeyPath, pgpPrivateKeyPath, pgpPassphrase, pgpService, aesService);
            await service.InitializeAesKeyAsync();
            return service;
        }

        private async Task InitializeAesKeyAsync()
        {
            var aesKeyPath = Path.Combine(_dataFolderPath, AesKeyFileName);
            if (File.Exists(aesKeyPath))
            {
                // Key exists, decrypt it
                var encryptedKey = await File.ReadAllTextAsync(aesKeyPath);
                _aesKey = _pgpService.DecryptString(encryptedKey, _pgpPrivateKeyPath, _pgpPassphrase);
            }
            else
            {
                // Key doesn't exist, create it
                using var rng = RandomNumberGenerator.Create();
                var keyBytes = new byte[32]; // 256-bit key
                rng.GetBytes(keyBytes);
                _aesKey = Convert.ToBase64String(keyBytes);

                // Encrypt and save the new key
                var encryptedKey = _pgpService.EncryptString(_aesKey, _pgpPublicKeyPath);
                await File.WriteAllTextAsync(aesKeyPath, encryptedKey);
            }
        }

        private static void ValidatePublicKeyFile(string publicKeyPath)
        {
            try
            {
                using var publicKeyStream = File.OpenRead(publicKeyPath);
                PgpEncryptionHelper.ReadPublicKey(publicKeyStream);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Invalid public key file: " + ex.Message, ex);
            }
        }

        // Decrypts the PGP file and loads entries
        public async Task<List<PasswordEntry>> LoadEntriesAsync()
        {
            var vaultPath = Path.Combine(_dataFolderPath, VaultFileName);
            if (!File.Exists(vaultPath))
            {
                return new List<PasswordEntry>(); // No vault file yet, return empty list
            }

            var decryptedPath = Path.GetTempFileName();
            try
            {
                _pgpService.DecryptFile(vaultPath, decryptedPath, _pgpPrivateKeyPath, _pgpPassphrase);
                var entries = await _jsonHandler.ReadEntriesAsync(decryptedPath);
                return entries;
            }
            finally
            {
                SecureFileHandler.SecureDelete(decryptedPath);
            }
        }

        // Saves entries to JSON and encrypts the file with PGP
        public async Task SaveEntriesAsync(List<PasswordEntry> entries)
        {
            var vaultPath = Path.Combine(_dataFolderPath, VaultFileName);
            var tempPath = Path.GetTempFileName();
            try
            {
                await _jsonHandler.WriteEntriesAsync(tempPath, entries);
                _pgpService.EncryptFile(tempPath, vaultPath, _pgpPublicKeyPath);
            }
            finally
            {
                SecureFileHandler.SecureDelete(tempPath);
            }
        }

        // Adds a new password entry with encryption
        public async Task AddEntryAsync(PasswordEntry entry, string plainPassword)
        {
            var entries = await LoadEntriesAsync();
            var (cipherText, iv) = _aesService.Encrypt(plainPassword, _aesKey);
            entry.EncryptedPassword = cipherText;
            entry.Iv = iv;
            entry.CreationTime = DateTime.UtcNow;
            entry.LastUpdateTime = DateTime.UtcNow;

            entries.Add(entry);
            await SaveEntriesAsync(entries);
        }

        // Updates an existing password entry
        public async Task UpdateEntryAsync(Guid id, Action<PasswordEntry> updateAction)
        {
            var entries = await LoadEntriesAsync();
            var entry = entries.FirstOrDefault(e => e.Id == id);
            if (entry != null)
            {
                updateAction(entry);
                entry.LastUpdateTime = DateTime.UtcNow;
                await SaveEntriesAsync(entries);
            }
        }

        // Deletes a password entry by ID
        public async Task DeleteEntryAsync(Guid id)
        {
            var entries = await LoadEntriesAsync();
            entries.RemoveAll(e => e.Id == id);
            await SaveEntriesAsync(entries);
        }

        // Retrieves a password entry by ID
        public async Task<PasswordEntry?> GetEntryByIdAsync(Guid id)
        {
            var entries = await LoadEntriesAsync();
            return entries.FirstOrDefault(e => e.Id == id);
        }

        // Retrieves all password entries
        public async Task<List<PasswordEntry>> GetAllEntriesAsync()
        {
            return await LoadEntriesAsync();
        }

        // Finds password entries based on a predicate
        public async Task<List<PasswordEntry>> FindEntriesAsync(Func<PasswordEntry, bool> predicate)
        {
            var entries = await LoadEntriesAsync();
            return entries.Where(predicate).ToList();
        }

        // Finds password entries based on a search term
        public async Task ChangePasswordAsync(Guid id, string newPlainPassword)
        {
            var entries = await LoadEntriesAsync();
            var entry = entries.FirstOrDefault(e => e.Id == id);
            if (entry != null)
            {
                var (cipherText, iv) = _aesService.Encrypt(newPlainPassword, _aesKey);
                entry.EncryptedPassword = cipherText;
                entry.Iv = iv;
                entry.LastUpdateTime = DateTime.UtcNow;
                await SaveEntriesAsync(entries);
            }
        }

        // Sets the expiration time for a password entry
        public async Task SetExpireTimeAsync(Guid id, DateTime? expireTime)
        {
            var entries = await LoadEntriesAsync();
            var entry = entries.FirstOrDefault(e => e.Id == id);
            if (entry != null)
            {
                entry.ExpireTime = expireTime;
                entry.LastUpdateTime = DateTime.UtcNow;
                await SaveEntriesAsync(entries);
            }
        }

        // Decrypts the password for a given entry
        // Returns an empty string if the entry is not valid or decryption fails
        public string DecryptPassword(PasswordEntry entry)
        {
            if (string.IsNullOrEmpty(entry.EncryptedPassword) || string.IsNullOrEmpty(entry.Iv))
                return string.Empty;
            return _aesService.Decrypt(entry.EncryptedPassword, _aesKey, entry.Iv);
        }        
    }
}
