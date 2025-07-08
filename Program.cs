using PasswordManager.Core.Models;
using PasswordManager.Core.Services;
namespace PasswordManager
{
    public class Program
    {
        private static async Task Main(string[] args)
        {
            Console.WriteLine("--- Secure Password Manager ---");
            Console.WriteLine("=============================");

            // 1. Get configuration from the user
            Console.Write("Enter the absolute path to your data folder: ");
            string? dataPath = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(dataPath) || !Directory.Exists(dataPath))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error: The provided path is invalid or does not exist.");
                Console.ResetColor();
                return;
            }

            Console.Write("Enter your Master Passphrase: ");
            string passphrase = ReadPassword();

            // 2. Initialize the service
            PasswordManagerService? service = null;
            try
            {
                // We pass null for key paths to use the default names ("public_key.asc", "private_key.asc")
                service = await PasswordManagerService.CreateAsync(dataPath, null, null, passphrase);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\nVault unlocked successfully!");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\nError unlocking vault: {ex.Message}");
                Console.WriteLine("Please check your passphrase and that the key files exist in the data folder.");
                Console.ResetColor();
                return;
            }

            // 3. Main application loop
            bool exit = false;
            while (!exit)
            {
                Console.WriteLine("\n--- Menu ---");
                Console.WriteLine("1. List all passwords");
                Console.WriteLine("2. Add a new password");
                Console.WriteLine("3. Exit");
                Console.Write("Select an option: ");

                switch (Console.ReadLine())
                {
                    case "1":
                        await ListAllPasswords(service);
                        break;
                    case "2":
                        await AddNewPassword(service);
                        break;
                    case "3":
                        exit = true;
                        break;
                    default:
                        Console.WriteLine("Invalid option, please try again.");
                        break;
                }
            }

            Console.WriteLine("\nExiting application. Goodbye!");
        }

        private static async Task ListAllPasswords(PasswordManagerService service)
        {
            Console.WriteLine("\n--- Your Saved Passwords ---");
            var entries = await service.GetAllEntriesAsync();

            if (!entries.Any())
            {
                Console.WriteLine("No entries found.");
                return;
            }

            foreach (var entry in entries)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"Site:     {entry.Site}");
                Console.ResetColor();
                Console.WriteLine($"Username: {entry.Username}");
                Console.WriteLine($"Email:    {entry.Email}");
                
                // Decrypt and show the password
                string plainPassword = service.DecryptPassword(entry);
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine($"Password: {plainPassword}");
                Console.ResetColor();
                Console.WriteLine("------------------------------");
            }
        }

        private static async Task AddNewPassword(PasswordManagerService service)
        {
            Console.WriteLine("\n--- Add New Password Entry ---");
            var newEntry = new PasswordEntry();

            Console.Write("Site/Application: ");
            newEntry.Site = Console.ReadLine() ?? string.Empty;

            Console.Write("Username: ");
            newEntry.Username = Console.ReadLine() ?? string.Empty;

            Console.Write("Email (optional): ");
            newEntry.Email = Console.ReadLine() ?? string.Empty;

            Console.Write("Password: ");
            string plainPassword = Console.ReadLine() ?? string.Empty;

            await service.AddEntryAsync(newEntry, plainPassword);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Entry added successfully!");
            Console.ResetColor();
        }

        /// <summary>
        /// Reads a password from the console without displaying it.
        /// </summary>
        private static string ReadPassword()
        {
            var pass = string.Empty;
            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && pass.Length > 0)
                {
                    Console.Write("\b \b");
                    pass = pass[0..^1];
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    pass += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);
            return pass;
        }
    }
}