using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Services;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;

namespace PasswordManager.Console
{
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            System.Console.WriteLine("--- Secure Password Manager ---");
            System.Console.WriteLine("================================");

            System.Console.Write("Enter the absolute path to your data folder: ");
            string? dataPath = System.Console.ReadLine();

            if (string.IsNullOrWhiteSpace(dataPath) || !Directory.Exists(dataPath))
            {
                WriteError("The provided path is invalid or does not exist.");
                return;
            }

            System.Console.Write("Enter your Master Passphrase: ");
            string passphrase = ReadPassword();
            System.Console.WriteLine();

            PasswordManagerService? service = null;
            try
            {
                var vaultKey = VaultKeyRing.Unlock(dataPath, passphrase);
                byte[] blobKey, fieldKey;
                try
                {
                    blobKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.BlobKeyInfo);
                    fieldKey = VaultKeyRing.DeriveSubkey(vaultKey, VaultKeyRing.FieldKeyInfo);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(vaultKey);
                }

                var repository = new KekVaultRepository(blobKey, dataPath);
                service = await PasswordManagerService.CreateAsync(repository, new AesService(), fieldKey);
                WriteSuccess("Vault unlocked successfully!");
            }
            catch (Exception ex)
            {
                WriteError($"Error unlocking vault: {ex.Message}");
                return;
            }

            using (service)
            {
                bool exit = false;
                while (!exit)
                {
                    System.Console.WriteLine("\n--- Menu ---");
                    System.Console.WriteLine("1. List all passwords");
                    System.Console.WriteLine("2. Add a new password");
                    System.Console.WriteLine("3. Exit");
                    System.Console.Write("Select an option: ");

                    switch (System.Console.ReadLine())
                    {
                        case "1": await ListAllPasswords(service); break;
                        case "2": await AddNewPassword(service); break;
                        case "3": exit = true; break;
                        default: System.Console.WriteLine("Invalid option."); break;
                    }
                }
            }

            System.Console.WriteLine("\nExiting. Goodbye!");
        }

        private static async Task ListAllPasswords(PasswordManagerService service)
        {
            System.Console.WriteLine("\n--- Saved Passwords ---");
            var entries = await service.GetEntriesAsync<ServiceEntry>();

            if (!entries.Any())
            {
                System.Console.WriteLine("No entries found.");
                return;
            }

            foreach (var entry in entries)
            {
                System.Console.ForegroundColor = ConsoleColor.Yellow;
                System.Console.WriteLine($"Site:     {entry.Site}");
                System.Console.ResetColor();

                foreach (var cred in entry.Credentials)
                {
                    if (!string.IsNullOrEmpty(cred.Label))
                        System.Console.WriteLine($"  [{cred.Label}]");

                    foreach (var field in cred.Fields)
                    {
                        var label = string.IsNullOrEmpty(field.Label) ? field.Type.ToString() : field.Label;
                        var value = field.IsSecret ? service.DecryptSecret(field) : field.PlainValue;
                        if (field.IsSecret) System.Console.ForegroundColor = ConsoleColor.Cyan;
                        System.Console.WriteLine($"  {label,-10}: {value}");
                        if (field.IsSecret) System.Console.ResetColor();
                    }
                }

                if (entry.Tags.Count > 0)
                    System.Console.WriteLine($"Tags:     {string.Join(", ", entry.Tags)}");
                System.Console.WriteLine(new string('-', 30));
            }
        }

        private static async Task AddNewPassword(PasswordManagerService service)
        {
            System.Console.WriteLine("\n--- Add New Entry ---");
            var entry = new ServiceEntry();

            System.Console.Write("Site/Application: ");
            entry.Site = System.Console.ReadLine() ?? string.Empty;

            var cred = new Credential();

            System.Console.Write("Username (optional): ");
            var username = System.Console.ReadLine() ?? string.Empty;
            if (!string.IsNullOrEmpty(username))
                cred.Fields.Add(new CredentialField { Type = CredentialFieldType.Username, PlainValue = username });

            System.Console.Write("Email (optional): ");
            var email = System.Console.ReadLine() ?? string.Empty;
            if (!string.IsNullOrEmpty(email))
                cred.Fields.Add(new CredentialField { Type = CredentialFieldType.Email, PlainValue = email });

            System.Console.Write("Password: ");
            string plain = System.Console.ReadLine() ?? string.Empty;
            cred.Fields.Add(new CredentialField
            {
                Type = CredentialFieldType.Password,
                IsSecret = true,
                SecretValue = service.EncryptValue(plain),
            });

            entry.Credentials.Add(cred);

            try
            {
                await service.AddServiceEntryAsync(entry);
                WriteSuccess("Entry added successfully!");
            }
            catch (Exception ex)
            {
                WriteError($"Error: {ex.Message}");
            }
        }

        private static string ReadPassword()
        {
            var pass = string.Empty;
            ConsoleKey key;
            do
            {
                var keyInfo = System.Console.ReadKey(intercept: true);
                key = keyInfo.Key;
                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    System.Console.Write("\b \b");
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    System.Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);
            return pass;
        }

        private static void WriteError(string msg)
        {
            System.Console.ForegroundColor = ConsoleColor.Red;
            System.Console.WriteLine($"Error: {msg}");
            System.Console.ResetColor();
        }

        private static void WriteSuccess(string msg)
        {
            System.Console.ForegroundColor = ConsoleColor.Green;
            System.Console.WriteLine(msg);
            System.Console.ResetColor();
        }
    }
}
