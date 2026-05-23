using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PasswordManager.Core.Configuration;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Services;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;
using PasswordManager.Infrastructure.Services;

namespace PasswordManager.Infrastructure
{
    public static class DependencyInjection
    {
        /// <summary>
        /// Registers all password manager services. Pass an action to configure AuthOptions
        /// (typically the app data path).
        /// </summary>
        public static IServiceCollection AddPasswordManager(
            this IServiceCollection services,
            Action<AuthOptions>? configureAuth = null)
        {
            var authOptions = new AuthOptions();
            configureAuth?.Invoke(authOptions);
            services.AddSingleton(authOptions);

            services.AddSingleton<IAesService, AesService>();
            services.AddSingleton<IPgpService, PgpService>();

            services.AddSingleton<IPasswordGenerator, PasswordGenerator>();
            services.AddSingleton<ITotpService, TotpService>();
            services.AddSingleton<IImportExportService, ImportExportService>();
            services.AddSingleton<IVaultAuditor, VaultAuditor>();
            services.AddSingleton<IAuthService, AuthService>();
            services.AddSingleton<IFileEncryptionService, FileEncryptionService>();
            services.AddSingleton<IKeyDirectoryService, KeyDirectoryService>();

            return services;
        }
    }
}
