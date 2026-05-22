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
        /// Registers all password manager services. Call Configure&lt;VaultOptions&gt; before this,
        /// or pass an Action to configure inline.
        /// </summary>
        public static IServiceCollection AddPasswordManager(
            this IServiceCollection services,
            Action<VaultOptions>? configure = null)
        {
            if (configure is not null)
                services.Configure(configure);

            services.AddSingleton<IAesService, AesService>();
            services.AddSingleton<IPgpService, PgpService>();

            services.AddSingleton<IVaultRepository>(sp =>
            {
                var options = sp.GetRequiredService<IOptions<VaultOptions>>().Value;
                var pgp = sp.GetRequiredService<IPgpService>();
                return new PgpVaultRepository(pgp, options);
            });

            services.AddSingleton<IPasswordGenerator, PasswordGenerator>();
            services.AddSingleton<ITotpService, TotpService>();
            services.AddSingleton<IImportExportService, ImportExportService>();
            services.AddSingleton<IVaultAuditor, VaultAuditor>();

            return services;
        }

        /// <summary>
        /// Creates and initializes a PasswordManagerService from the DI container.
        /// Call this during app startup after building the ServiceProvider.
        /// </summary>
        public static async Task<PasswordManagerService> CreatePasswordManagerAsync(
            this IServiceProvider sp)
        {
            var options = sp.GetRequiredService<IOptions<VaultOptions>>().Value;
            return await PasswordManagerService.CreateAsync(
                sp.GetRequiredService<IVaultRepository>(),
                sp.GetRequiredService<IAesService>(),
                sp.GetRequiredService<IPgpService>(),
                options);
        }
    }
}
