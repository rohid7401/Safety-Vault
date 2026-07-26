using System.Security.Cryptography;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Models;
using PasswordManager.Core.Services;
using PasswordManager.Infrastructure.Encryption;
using PasswordManager.Infrastructure.Persistence;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class PasswordManagerServiceTests : IDisposable
    {
        private readonly string _dataDir =
            Path.Combine(Path.GetTempPath(), "pmgr_test_" + Guid.NewGuid().ToString("N"));

        // Fixed for the lifetime of the test — each service/repository instance gets its
        // own clone, since both zeroize their copy on Dispose.
        private readonly byte[] _blobKey = RandomNumberGenerator.GetBytes(32);
        private readonly byte[] _fieldKey = RandomNumberGenerator.GetBytes(32);

        public PasswordManagerServiceTests() => Directory.CreateDirectory(_dataDir);

        private Task<PasswordManagerService> CreateServiceAsync()
        {
            var repository = new KekVaultRepository((byte[])_blobKey.Clone(), _dataDir);
            return PasswordManagerService.CreateAsync(repository, new AesService(), (byte[])_fieldKey.Clone());
        }

        // ─── Helpers: build/read a simple single-credential service entry ─────

        private static async Task<ServiceEntry> AddPwAsync(
            PasswordManagerService svc, string site, string password = "pass",
            string username = "", string[]? tags = null)
        {
            var cred = new Credential();
            if (!string.IsNullOrEmpty(username))
                cred.Fields.Add(new CredentialField { Type = CredentialFieldType.Username, PlainValue = username });
            cred.Fields.Add(new CredentialField
            {
                Type = CredentialFieldType.Password,
                IsSecret = true,
                SecretValue = svc.EncryptValue(password),
            });

            var entry = new ServiceEntry { Site = site };
            if (tags != null) entry.Tags.AddRange(tags);
            entry.Credentials.Add(cred);

            await svc.AddServiceEntryAsync(entry);
            return entry;
        }

        private static CredentialField PwField(ServiceEntry e) =>
            e.Credentials[0].Fields.First(f => f.Type == CredentialFieldType.Password);

        private static string Pw(PasswordManagerService svc, ServiceEntry e) =>
            svc.DecryptSecret(PwField(e));

        // ─── Initialization ──────────────────────────────────────────────────

        [Fact]
        public async Task CreateAsync_ReturnsService()
        {
            await using var svc = await CreateServiceAsync();
            Assert.NotNull(svc);
        }

        [Fact]
        public async Task GetAllEntriesAsync_WrongBlobKey_ThrowsVaultIntegrityException()
        {
            await using (var svc = await CreateServiceAsync())
                await AddPwAsync(svc, "s.com");

            var wrongRepo = new KekVaultRepository(RandomNumberGenerator.GetBytes(32), _dataDir);
            await using var wrongSvc = await PasswordManagerService.CreateAsync(
                wrongRepo, new AesService(), RandomNumberGenerator.GetBytes(32));

            await Assert.ThrowsAsync<VaultIntegrityException>(() => wrongSvc.GetAllEntriesAsync());
        }

        // ─── Ensure PGP key files ────────────────────────────────────────────

        [Fact]
        public async Task EnsurePgpKeyFilesAsync_RestoresMissingFilesFromVault()
        {
            const string publicArmor = "-----BEGIN PGP PUBLIC KEY-----\nfake\n-----END-----";
            const string privateArmor = "-----BEGIN PGP PRIVATE KEY-----\nfake\n-----END-----";

            await using (var svc = await CreateServiceAsync())
            {
                var vault = await svc.GetAllEntriesAsync(); // ensure vault file exists
                Assert.Empty(vault);

                var repo = new KekVaultRepository((byte[])_blobKey.Clone(), _dataDir);
                await repo.SaveAsync(new VaultData
                {
                    PgpPublicKeyArmored = publicArmor,
                    PgpPrivateKeyArmored = privateArmor,
                });
                repo.Dispose();
            }

            await using var svc2 = await CreateServiceAsync();
            await svc2.EnsurePgpKeyFilesAsync(_dataDir);

            Assert.Equal(publicArmor, await File.ReadAllTextAsync(Path.Combine(_dataDir, "public_key.asc")));
            Assert.Equal(privateArmor, await File.ReadAllTextAsync(Path.Combine(_dataDir, "private_key.asc")));
        }

        [Fact]
        public async Task EnsurePgpKeyFilesAsync_DoesNotOverwriteExistingFiles()
        {
            var publicPath = Path.Combine(_dataDir, "public_key.asc");
            await File.WriteAllTextAsync(publicPath, "already-here");

            await using var svc = await CreateServiceAsync();
            await svc.EnsurePgpKeyFilesAsync(_dataDir);

            Assert.Equal("already-here", await File.ReadAllTextAsync(publicPath));
        }

        // ─── Empty vault ─────────────────────────────────────────────────────

        [Fact]
        public async Task GetAllEntriesAsync_EmptyVault_ReturnsEmptyList()
        {
            await using var svc = await CreateServiceAsync();
            Assert.Empty(await svc.GetAllEntriesAsync());
        }

        // ─── Add service entry ───────────────────────────────────────────────

        [Fact]
        public async Task AddServiceEntryAsync_PersistsEntry()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "example.com", "secret123", username: "alice");

            var all = await svc.GetAllEntriesAsync();
            Assert.Single(all);
            var entry = Assert.IsType<ServiceEntry>(all[0]);
            Assert.Equal("example.com", entry.Site);
        }

        [Fact]
        public async Task AddServiceEntryAsync_EncryptsPasswordWithGcm()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "s.com", "plaintext");

            var entry = (await svc.GetEntriesAsync<ServiceEntry>())[0];
            var field = PwField(entry);
            Assert.NotEqual("plaintext", field.SecretValue!.CipherText);
            Assert.False(string.IsNullOrEmpty(field.SecretValue.Nonce));
            Assert.False(string.IsNullOrEmpty(field.SecretValue.Tag));
        }

        [Fact]
        public async Task AddServiceEntryAsync_MultipleEntries()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "a.com", "p1");
            await AddPwAsync(svc, "b.com", "p2");
            await AddPwAsync(svc, "c.com", "p3");

            Assert.Equal(3, (await svc.GetAllEntriesAsync()).Count);
        }

        // ─── Add secure note ─────────────────────────────────────────────────

        [Fact]
        public async Task AddSecureNoteAsync_PersistsAndDecrypts()
        {
            await using var svc = await CreateServiceAsync();
            var note = new SecureNote { Title = "SSH Key", Label = "servers" };
            await svc.AddSecureNoteAsync(note, "my private key content");

            var notes = await svc.GetEntriesAsync<SecureNote>();
            Assert.Single(notes);
            Assert.Equal("SSH Key", notes[0].Title);
            Assert.Equal("my private key content", svc.DecryptField(notes[0].Content));
        }

        // ─── Add card entry ──────────────────────────────────────────────────

        [Fact]
        public async Task AddCardEntryAsync_PersistsAndDecrypts()
        {
            await using var svc = await CreateServiceAsync();
            var card = new CardEntry
            {
                CardholderName = "John Doe",
                ExpiryMonth = 12,
                ExpiryYear = 2028
            };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123");

            var cards = await svc.GetEntriesAsync<CardEntry>();
            Assert.Single(cards);
            Assert.Equal("John Doe", cards[0].CardholderName);
            Assert.Equal("4111111111111111", svc.DecryptField(cards[0].CardNumber));
            Assert.Equal("123", svc.DecryptField(cards[0].Cvv));
        }

        // ─── Mixed entry types ───────────────────────────────────────────────

        [Fact]
        public async Task GetAllEntriesAsync_ReturnsMixedTypes()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "git.com", "p");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "Note" }, "text");
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "Jane" }, "4111", "999");

            var all = await svc.GetAllEntriesAsync();
            Assert.Equal(3, all.Count);
            Assert.Single(all.OfType<ServiceEntry>());
            Assert.Single(all.OfType<SecureNote>());
            Assert.Single(all.OfType<CardEntry>());
        }

        [Fact]
        public async Task GetEntriesAsync_FiltersByType()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "a.com", "p1");
            await AddPwAsync(svc, "b.com", "p2");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "Note" }, "text");

            Assert.Equal(2, (await svc.GetEntriesAsync<ServiceEntry>()).Count);
            Assert.Single(await svc.GetEntriesAsync<SecureNote>());
            Assert.Empty(await svc.GetEntriesAsync<CardEntry>());
        }

        // ─── Tags ────────────────────────────────────────────────────────────

        [Fact]
        public async Task Tags_PersistOnEntries()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "work.com", "pass", tags: new[] { "work", "dev" });

            var stored = (await svc.GetEntriesAsync<ServiceEntry>())[0];
            Assert.Equal(2, stored.Tags.Count);
            Assert.Contains("work", stored.Tags);
            Assert.Contains("dev", stored.Tags);
        }

        [Fact]
        public async Task FindEntriesAsync_ByTag()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "a.com", "p1", tags: new[] { "personal" });
            await AddPwAsync(svc, "b.com", "p2", tags: new[] { "work" });
            await svc.AddSecureNoteAsync(new SecureNote { Title = "N", Tags = { "work" } }, "t");

            var workEntries = await svc.FindEntriesAsync(e => e.Tags.Contains("work"));
            Assert.Equal(2, workEntries.Count);
        }

        // ─── Decrypt ─────────────────────────────────────────────────────────

        [Fact]
        public async Task DecryptSecret_ReturnsOriginalPlaintext()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "s.com", "my-secret-password");

            var stored = (await svc.GetEntriesAsync<ServiceEntry>())[0];
            Assert.Equal("my-secret-password", Pw(svc, stored));
        }

        [Fact]
        public async Task DecryptSecret_UnicodePlaintext_RoundTrips()
        {
            await using var svc = await CreateServiceAsync();
            const string unicode = "P@ñoño-🔐-Ünïcödé-密码";
            await AddPwAsync(svc, "s.com", unicode);

            var stored = (await svc.GetEntriesAsync<ServiceEntry>())[0];
            Assert.Equal(unicode, Pw(svc, stored));
        }

        // ─── Get by ID ───────────────────────────────────────────────────────

        [Fact]
        public async Task GetEntryByIdAsync_ExistingId_ReturnsEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "find.me");

            var found = await svc.GetEntryByIdAsync(entry.Id);
            Assert.NotNull(found);
            Assert.Equal("find.me", Assert.IsType<ServiceEntry>(found).Site);
        }

        [Fact]
        public async Task GetEntryByIdAsync_MissingId_ReturnsNull()
        {
            await using var svc = await CreateServiceAsync();
            Assert.Null(await svc.GetEntryByIdAsync(Guid.NewGuid()));
        }

        // ─── Find ────────────────────────────────────────────────────────────

        [Fact]
        public async Task FindEntriesAsync_MatchingPredicate()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "github.com", "p1");
            await AddPwAsync(svc, "gitlab.com", "p2");
            await AddPwAsync(svc, "amazon.com", "p3");

            var git = await svc.FindEntriesAsync(e => e is ServiceEntry p && p.Site.StartsWith("git"));
            Assert.Equal(2, git.Count);
        }

        // ─── Update ──────────────────────────────────────────────────────────

        [Fact]
        public async Task UpdateEntryAsync_ModifiesField()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "old.com");

            await svc.UpdateEntryAsync(entry.Id, e => ((ServiceEntry)e).Site = "new.com");

            var updated = Assert.IsType<ServiceEntry>(await svc.GetEntryByIdAsync(entry.Id));
            Assert.Equal("new.com", updated.Site);
        }

        [Fact]
        public async Task UpdateEntryAsync_NonExistentId_DoesNotThrow()
        {
            await using var svc = await CreateServiceAsync();
            var ex = await Record.ExceptionAsync(() => svc.UpdateEntryAsync(Guid.NewGuid(), _ => { }));
            Assert.Null(ex);
        }

        // ─── Rotate field secret ─────────────────────────────────────────────

        [Fact]
        public async Task RotateFieldSecretAsync_UpdatesDecryptedPassword()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "s.com", "old-password");
            var cred = entry.Credentials[0];
            var field = PwField(entry);

            var ok = await svc.RotateFieldSecretAsync(entry.Id, cred.Id, field.Id, "new-password");
            Assert.True(ok);

            var stored = Assert.IsType<ServiceEntry>(await svc.GetEntryByIdAsync(entry.Id));
            Assert.Equal("new-password", Pw(svc, stored));
        }

        [Fact]
        public async Task RotateFieldSecretAsync_UnknownIds_ReturnsFalse()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "s.com");

            var ok = await svc.RotateFieldSecretAsync(entry.Id, Guid.NewGuid(), Guid.NewGuid(), "x");
            Assert.False(ok);
        }

        // ─── Soft delete ─────────────────────────────────────────────────────

        [Fact]
        public async Task DeleteEntryAsync_SoftDeletesEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "delete.me");

            await svc.DeleteEntryAsync(entry.Id);

            Assert.Empty(await svc.GetAllEntriesAsync());
            var deleted = await svc.GetDeletedEntriesAsync();
            Assert.Single(deleted);
            Assert.Equal(entry.Id, deleted[0].Id);
            Assert.True(deleted[0].IsDeleted);
            Assert.NotNull(deleted[0].DeletedAt);
        }

        [Fact]
        public async Task RestoreEntryAsync_RestoresSoftDeletedEntry()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "restore.me");
            await svc.DeleteEntryAsync(entry.Id);

            await svc.RestoreEntryAsync(entry.Id);

            Assert.Single(await svc.GetAllEntriesAsync());
            Assert.Empty(await svc.GetDeletedEntriesAsync());
        }

        [Fact]
        public async Task PurgeDeletedAsync_PermanentlyRemovesDeletedEntries()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "keep.me", "p1");
            var toDelete = await AddPwAsync(svc, "purge.me", "p2");
            await svc.DeleteEntryAsync(toDelete.Id);

            await svc.PurgeDeletedAsync();

            Assert.Single(await svc.GetAllEntriesAsync());
            Assert.Empty(await svc.GetDeletedEntriesAsync());
        }

        [Fact]
        public async Task DeleteEntryAsync_NonExistentId_DoesNotThrow()
        {
            await using var svc = await CreateServiceAsync();
            var ex = await Record.ExceptionAsync(() => svc.DeleteEntryAsync(Guid.NewGuid()));
            Assert.Null(ex);
        }

        // ─── Expiration ──────────────────────────────────────────────────────

        [Fact]
        public async Task SetExpireTimeAsync_PersistsExpiration()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "expiring.com");

            var expiry = DateTime.UtcNow.AddDays(30);
            await svc.SetExpireTimeAsync(entry.Id, expiry);

            var stored = await svc.GetEntryByIdAsync(entry.Id);
            Assert.NotNull(stored!.ExpireTime);
            Assert.Equal(expiry, stored.ExpireTime!.Value, TimeSpan.FromSeconds(1));
        }

        // ─── Persistence across sessions ─────────────────────────────────────

        [Fact]
        public async Task Entries_PersistAcrossServiceInstances()
        {
            await using (var svc = await CreateServiceAsync())
                await AddPwAsync(svc, "persist.com", "abc", username: "bob");

            await using var svc2 = await CreateServiceAsync();
            var all = await svc2.GetAllEntriesAsync();
            Assert.Single(all);
            Assert.Equal("persist.com", Assert.IsType<ServiceEntry>(all[0]).Site);
        }

        [Fact]
        public async Task MixedTypes_PersistAcrossServiceInstances()
        {
            await using (var svc = await CreateServiceAsync())
            {
                await AddPwAsync(svc, "a.com", "p");
                await svc.AddSecureNoteAsync(new SecureNote { Title = "N" }, "text");
                await svc.AddCardEntryAsync(new CardEntry { CardholderName = "J" }, "4111", "123");
            }

            await using var svc2 = await CreateServiceAsync();
            var all = await svc2.GetAllEntriesAsync();
            Assert.Equal(3, all.Count);
            Assert.Single(all.OfType<ServiceEntry>());
            Assert.Single(all.OfType<SecureNote>());
            Assert.Single(all.OfType<CardEntry>());

            var card = all.OfType<CardEntry>().First();
            Assert.Equal("4111", svc2.DecryptField(card.CardNumber));
        }

        // ─── Native backup round trip (device → device) ──────────────────────

        [Fact]
        public async Task ExportBackup_ThenImportIntoAnotherVault_PreservesEverything()
        {
            VaultBackup backup;

            await using (var source = await CreateServiceAsync())
            {
                var entry = new ServiceEntry { Site = "bank.com", Grouped = true, Tags = { "finance" } };

                var personal = new Credential { Label = "Personal" };
                personal.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.Email,
                    PlainValue = "me@bank.com",
                });
                personal.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.Password,
                    IsSecret = true,
                    SecretValue = source.EncryptValue("P@ssw0rd"),
                    Rotation = new RotationPolicy { Interval = 30, Unit = RotationUnit.Days },
                });
                personal.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.Pin,
                    IsSecret = true,
                    Label = "ATM PIN",
                    SecretValue = source.EncryptValue("4821"),
                });

                var business = new Credential { Label = "Business" };
                business.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.Username,
                    PlainValue = "acme",
                });
                business.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.TwoFactor,
                    IsSecret = true,
                    SecretValue = source.EncryptValue("JBSWY3DPEHPK3PXP"),
                    TwoFactorKind = TwoFactorKind.Hotp,
                    HotpCounter = 7,
                });

                entry.Credentials.Add(personal);
                entry.Credentials.Add(business);
                await source.AddServiceEntryAsync(entry);

                backup = await source.ExportBackupAsync();
            }

            // A different vault, with a different field key — the whole reason the backup
            // carries plaintext rather than the stored ciphertexts.
            var otherDir = Path.Combine(_dataDir, "other");
            Directory.CreateDirectory(otherDir);
            var otherRepo = new KekVaultRepository(RandomNumberGenerator.GetBytes(32), otherDir);
            await using var target = await PasswordManagerService.CreateAsync(
                otherRepo, new AesService(), RandomNumberGenerator.GetBytes(32));

            var added = await target.ImportBackupAsync(backup);
            Assert.Equal(1, added);

            var restored = Assert.Single(await target.GetEntriesAsync<ServiceEntry>());
            Assert.Equal("bank.com", restored.Site);
            Assert.Equal(new[] { "finance" }, restored.Tags);
            Assert.True(restored.Grouped);
            Assert.Equal(2, restored.Credentials.Count);

            var restoredPersonal = restored.Credentials.Single(c => c.Label == "Personal");
            Assert.Equal("me@bank.com",
                restoredPersonal.Fields.Single(f => f.Type == CredentialFieldType.Email).PlainValue);

            var password = restoredPersonal.Fields.Single(f => f.Type == CredentialFieldType.Password);
            Assert.Equal("P@ssw0rd", target.DecryptSecret(password));
            Assert.NotNull(password.Rotation);
            Assert.Equal(30, password.Rotation!.Interval);

            var pin = restoredPersonal.Fields.Single(f => f.Type == CredentialFieldType.Pin);
            Assert.Equal("4821", target.DecryptSecret(pin));
            Assert.Equal("ATM PIN", pin.Label);

            var restoredBusiness = restored.Credentials.Single(c => c.Label == "Business");
            var totp = restoredBusiness.Fields.Single(f => f.Type == CredentialFieldType.TwoFactor);
            Assert.Equal("JBSWY3DPEHPK3PXP", target.DecryptSecret(totp));
            Assert.Equal(TwoFactorKind.Hotp, totp.TwoFactorKind);
            Assert.Equal(7, totp.HotpCounter);
        }

        [Fact]
        public async Task ImportBackup_GivesFreshIds_SoReimportingDuplicatesRatherThanOverwrites()
        {
            await using var svc = await CreateServiceAsync();
            var original = await AddPwAsync(svc, "a.com");

            var backup = await svc.ExportBackupAsync();
            await svc.ImportBackupAsync(backup);

            var all = await svc.GetEntriesAsync<ServiceEntry>();
            Assert.Equal(2, all.Count);
            Assert.Equal(2, all.Select(e => e.Id).Distinct().Count());
            Assert.Contains(all, e => e.Id == original.Id);
        }

        // ─── Interop export rows ─────────────────────────────────────────────

        [Fact]
        public async Task ExportRowsAsync_EmitsOneRowPerCredential()
        {
            await using var svc = await CreateServiceAsync();

            var entry = new ServiceEntry { Site = "bank.com" };
            foreach (var label in new[] { "Personal", "Business" })
            {
                var cred = new Credential { Label = label };
                cred.Fields.Add(new CredentialField
                {
                    Type = CredentialFieldType.Password,
                    IsSecret = true,
                    SecretValue = svc.EncryptValue($"pw-{label}"),
                });
                entry.Credentials.Add(cred);
            }
            await svc.AddServiceEntryAsync(entry);

            var rows = await svc.ExportRowsAsync();

            Assert.Equal(2, rows.Count);
            Assert.All(rows, r => Assert.Equal("bank.com", r.Site));
            Assert.Equal(new[] { "Personal", "Business" }, rows.Select(r => r.CredentialLabel));
            Assert.Contains(rows, r => r.Password == "pw-Personal");
        }

        [Fact]
        public async Task ExportRowsAsync_CarriesFieldsTheFlatShapeUsedToDrop()
        {
            await using var svc = await CreateServiceAsync();

            var cred = new Credential();
            cred.Fields.Add(new CredentialField { Type = CredentialFieldType.Phone, PlainValue = "+506 8888" });
            cred.Fields.Add(new CredentialField
            {
                Type = CredentialFieldType.Pin,
                IsSecret = true,
                SecretValue = svc.EncryptValue("4821"),
            });
            cred.Fields.Add(new CredentialField
            {
                Type = CredentialFieldType.Text,
                Label = "Recovery",
                PlainValue = "code-99",
            });

            await svc.AddServiceEntryAsync(new ServiceEntry { Site = "a.com", Credentials = { cred } });

            var row = Assert.Single(await svc.ExportRowsAsync());

            Assert.Equal("+506 8888", row.Phone);
            Assert.Equal("4821", row.Pin);
            Assert.Equal("Recovery: code-99", row.Text);
        }

        // ─── Delete all (per-section reset) ──────────────────────────────────

        [Fact]
        public async Task DeleteAllAsync_RemovesOnlyThatType()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "a.com");
            await AddPwAsync(svc, "b.com");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "keep me" }, "content");

            var removed = await svc.DeleteAllAsync<ServiceEntry>();

            Assert.Equal(2, removed);
            Assert.Empty(await svc.GetEntriesAsync<ServiceEntry>());
            Assert.Single(await svc.GetEntriesAsync<SecureNote>());
        }

        [Fact]
        public async Task DeleteAllAsync_AlsoRemovesTrashedEntriesOfThatType()
        {
            await using var svc = await CreateServiceAsync();
            var trashed = await AddPwAsync(svc, "gone.com");
            await AddPwAsync(svc, "live.com");
            await svc.DeleteEntryAsync(trashed.Id);

            var removed = await svc.DeleteAllAsync<ServiceEntry>();

            // Both the live one and the soft-deleted one: a "delete all" that left the
            // trash full would not actually shrink the vault.
            Assert.Equal(2, removed);
            Assert.Empty(await svc.GetDeletedEntriesAsync());
        }

        [Fact]
        public async Task DeleteAllAsync_SurvivesReopen()
        {
            var entryId = Guid.Empty;
            await using (var svc = await CreateServiceAsync())
            {
                entryId = (await AddPwAsync(svc, "a.com")).Id;
                await svc.DeleteAllAsync<ServiceEntry>();
            }

            await using var reopened = await CreateServiceAsync();
            Assert.Empty(await reopened.GetEntriesAsync<ServiceEntry>());
            Assert.Null(await reopened.GetEntryByIdAsync(entryId));
        }

        [Fact]
        public async Task DeleteAllAsync_EmptySection_ReturnsZero()
        {
            await using var svc = await CreateServiceAsync();
            Assert.Equal(0, await svc.DeleteAllAsync<CardEntry>());
        }

        [Fact]
        public async Task CountAsync_IgnoresTrashedEntries()
        {
            await using var svc = await CreateServiceAsync();
            var trashed = await AddPwAsync(svc, "gone.com");
            await AddPwAsync(svc, "live.com");
            await svc.DeleteEntryAsync(trashed.Id);

            Assert.Equal(1, await svc.CountAsync<ServiceEntry>());
        }

        // ─── IDisposable ─────────────────────────────────────────────────────

        [Fact]
        public async Task Dispose_ThenGetAllEntries_ThrowsObjectDisposedException()
        {
            var svc = await CreateServiceAsync();
            svc.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => svc.GetAllEntriesAsync());
        }

        public void Dispose()
        {
            try { Directory.Delete(_dataDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
