using System.Security.Cryptography;
using PasswordManager.Core.Models;
using PasswordManager.Core.Services;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>Tanda 2 — PasswordManagerService support for the flexible ServiceEntry model.</summary>
    public class ServiceEntryServiceTests : IDisposable
    {
        private readonly string _dataDir =
            Path.Combine(Path.GetTempPath(), "pmgr_test_" + Guid.NewGuid().ToString("N"));
        private readonly byte[] _blobKey = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _fieldKey = RandomNumberGenerator.GetBytes(32);

        public ServiceEntryServiceTests() => Directory.CreateDirectory(_dataDir);

        private Task<PasswordManagerService> CreateServiceAsync()
        {
            var repository = new KekVaultRepository((byte[])_blobKey.Clone(), _dataDir);
            return PasswordManagerService.CreateAsync(repository, new AesService(), (byte[])_fieldKey.Clone());
        }

        [Fact]
        public async Task AddServiceEntry_PersistsPlainAndSecretFields_AcrossSessions()
        {
            await using (var svc = await CreateServiceAsync())
            {
                var cred = new Credential { Label = "Personal" };
                cred.Fields.Add(new CredentialField { Type = CredentialFieldType.Email, PlainValue = "a@gmail.com" });
                cred.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.Password,
                    IsSecret = true,
                    SecretValue = svc.EncryptValue("s3cret"),
                });
                await svc.AddServiceEntryAsync(new ServiceEntry { Site = "Google", Credentials = { cred } });
            }

            // Fresh session: same field key re-derived, so secrets decrypt.
            await using var svc2 = await CreateServiceAsync();
            var loaded = Assert.Single(await svc2.GetEntriesAsync<ServiceEntry>());
            Assert.Equal("Google", loaded.Site);

            var fields = loaded.Credentials.Single().Fields;
            Assert.Equal("a@gmail.com", fields.First(f => f.Type == CredentialFieldType.Email).PlainValue);
            Assert.Equal("s3cret", svc2.DecryptSecret(fields.First(f => f.Type == CredentialFieldType.Password)));
        }

        [Fact]
        public async Task AddServiceEntry_SecretIsNotStoredInClear()
        {
            await using var svc = await CreateServiceAsync();
            var field = new CredentialField { Type = CredentialFieldType.Password, IsSecret = true, SecretValue = svc.EncryptValue("plaintext-pw") };
            await svc.AddServiceEntryAsync(new ServiceEntry { Site = "x", Credentials = { new Credential { Fields = { field } } } });

            var loaded = Assert.Single(await svc.GetEntriesAsync<ServiceEntry>());
            var stored = loaded.Credentials.Single().Fields.Single();
            Assert.NotEqual("plaintext-pw", stored.SecretValue!.CipherText);
            Assert.Empty(stored.PlainValue);
        }

        [Fact]
        public async Task RotateFieldSecret_KeepsPrevious_AndUpdatesCurrent()
        {
            await using var svc = await CreateServiceAsync();
            var field = new CredentialField
            {
                Type = CredentialFieldType.Password,
                IsSecret = true,
                Rotation = new RotationPolicy { Interval = 30 },
                SecretValue = svc.EncryptValue("v1"),
            };
            var cred = new Credential { Fields = { field } };
            var entry = new ServiceEntry { Site = "x", Credentials = { cred } };
            await svc.AddServiceEntryAsync(entry);

            Assert.True(await svc.RotateFieldSecretAsync(entry.Id, cred.Id, field.Id, "v2"));

            var f = (await svc.GetEntriesAsync<ServiceEntry>()).Single().Credentials.Single().Fields.Single();
            Assert.Equal("v2", svc.DecryptSecret(f));
            Assert.Equal("v1", svc.DecryptPreviousSecret(f));
        }

        [Fact]
        public async Task RotateFieldSecret_NoRotationPolicy_DoesNotKeepPrevious()
        {
            await using var svc = await CreateServiceAsync();
            var field = new CredentialField { Type = CredentialFieldType.Password, IsSecret = true, SecretValue = svc.EncryptValue("v1") };
            var cred = new Credential { Fields = { field } };
            var entry = new ServiceEntry { Site = "x", Credentials = { cred } };
            await svc.AddServiceEntryAsync(entry);

            await svc.RotateFieldSecretAsync(entry.Id, cred.Id, field.Id, "v2");

            var f = (await svc.GetEntriesAsync<ServiceEntry>()).Single().Credentials.Single().Fields.Single();
            Assert.Equal("v2", svc.DecryptSecret(f));
            Assert.Null(f.PreviousSecret);
        }

        [Fact]
        public async Task RotateFieldSecret_UnknownIds_ReturnsFalse()
        {
            await using var svc = await CreateServiceAsync();
            Assert.False(await svc.RotateFieldSecretAsync(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "x"));
        }

        public void Dispose()
        {
            try { Directory.Delete(_dataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
