using PasswordManager.Core.Configuration;
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

            var options = new VaultOptions { DataFolderPath = dataPath, Passphrase = passphrase };
            var pgpService = new PgpService();
            var repository = new PgpVaultRepository(pgpService, options);

            PasswordManagerService? service = null;
            try
            {
                service = await PasswordManagerService.CreateAsync(
                    repository, new AesService(), pgpService, options);
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
            var entries = await service.GetEntriesAsync<PasswordEntry>();

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
                System.Console.WriteLine($"Username: {entry.Username}");
                System.Console.WriteLine($"Email:    {entry.Email}");
                System.Console.ForegroundColor = ConsoleColor.Cyan;
                System.Console.WriteLine($"Password: {service.DecryptPassword(entry)}");
                System.Console.ResetColor();
                if (entry.Tags.Count > 0)
                    System.Console.WriteLine($"Tags:     {string.Join(", ", entry.Tags)}");
                System.Console.WriteLine(new string('-', 30));
            }
        }

        private static async Task AddNewPassword(PasswordManagerService service)
        {
            System.Console.WriteLine("\n--- Add New Entry ---");
            var entry = new PasswordEntry();

            System.Console.Write("Site/Application: ");
            entry.Site = System.Console.ReadLine() ?? string.Empty;

            System.Console.Write("Username: ");
            entry.Username = System.Console.ReadLine() ?? string.Empty;

            System.Console.Write("Email (optional): ");
            entry.Email = System.Console.ReadLine() ?? string.Empty;

            System.Console.Write("Password: ");
            string plain = System.Console.ReadLine() ?? string.Empty;

            try
            {
                await service.AddPasswordEntryAsync(entry, plain);
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
