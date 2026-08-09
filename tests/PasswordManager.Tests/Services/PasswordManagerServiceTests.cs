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

        /// <summary>
        /// A second vault with its own folder and its own keys — the other device. Sharing the
        /// folder and keys of <see cref="CreateServiceAsync"/> would make a "transfer" test read
        /// back the very entries it started from, and pass without proving anything.
        /// </summary>
        private Task<PasswordManagerService> CreateOtherDeviceAsync()
        {
            var dir = Path.Combine(_dataDir, "device_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var repository = new KekVaultRepository(RandomNumberGenerator.GetBytes(32), dir);
            return PasswordManagerService.CreateAsync(
                repository, new AesService(), RandomNumberGenerator.GetBytes(32));
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

        // ─── Own PGP identity (deferred generation) ─────────────────────────

        [Fact]
        public async Task HasOwnPgpIdentityAsync_FreshVault_ReturnsFalse()
        {
            await using var svc = await CreateServiceAsync();
            Assert.False(await svc.HasOwnPgpIdentityAsync());
        }

        [Fact]
        public async Task GenerateOwnPgpIdentityAsync_CreatesAndPersistsIdentity()
        {
            await using var svc = await CreateServiceAsync();
            await svc.GenerateOwnPgpIdentityAsync(
                new PgpService(), _dataDir, "correct-horse-battery-staple", "alice <alice@example.com>");

            Assert.True(await svc.HasOwnPgpIdentityAsync());
            Assert.True(File.Exists(Path.Combine(_dataDir, "public_key.asc")));
            Assert.True(File.Exists(Path.Combine(_dataDir, "private_key.asc")));
        }

        [Fact]
        public async Task GenerateOwnPgpIdentityAsync_AlreadyHasOne_DoesNotRegenerate()
        {
            await using (var svc = await CreateServiceAsync())
                await svc.GenerateOwnPgpIdentityAsync(
                    new PgpService(), _dataDir, "correct-horse-battery-staple", "alice <alice@example.com>");
            var firstPublicKey = await File.ReadAllTextAsync(Path.Combine(_dataDir, "public_key.asc"));

            await using (var svc2 = await CreateServiceAsync())
                await svc2.GenerateOwnPgpIdentityAsync(
                    new PgpService(), _dataDir, "a-different-phrase", "bob <bob@example.com>");

            Assert.Equal(firstPublicKey, await File.ReadAllTextAsync(Path.Combine(_dataDir, "public_key.asc")));
        }

        /// <summary>
        /// Regression test: the key's User ID used to be hardcoded to a placeholder address
        /// ("vault@safetyvault.local") regardless of the account's real email, which silently
        /// broke keyserver publishing — Hagrid indexes by the email inside the key's own UID, not
        /// by anything the app tells it out of band, so the key could never be found (or
        /// verified) by the address it was supposedly published under.
        /// </summary>
        [Fact]
        public async Task GenerateOwnPgpIdentityAsync_EmbedsGivenUserIdInTheKey()
        {
            await using var svc = await CreateServiceAsync();
            await svc.GenerateOwnPgpIdentityAsync(
                new PgpService(), _dataDir, "correct-horse-battery-staple", "alice <alice@example.com>");

            var armored = await File.ReadAllTextAsync(Path.Combine(_dataDir, "public_key.asc"));
            var details = new PgpService().InspectPublicKey(armored);

            Assert.True(details.HasUserIdFor("alice@example.com"));
        }

        // ─── Native backup v2: everything, with links intact ─────────────────

        [Fact]
        public async Task Backup_CarriesNotesAndCardsAndNotJustPasswords()
        {
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "github.com", "s3cret");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "Recovery" }, "1234-5678");
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "JANE" }, "4111111111111111", "123", "4821");

            var backup = await svc.ExportBackupAsync();

            Assert.Equal(VaultBackup.CurrentVersion, backup.Version);
            Assert.Single(backup.Services);
            Assert.Single(backup.Notes);
            Assert.Single(backup.Cards);
            Assert.Equal("1234-5678", backup.Notes[0].Content);
            Assert.Equal("4821", backup.Cards[0].Pin);
        }

        [Fact]
        public async Task ARoundTripThroughTheBackup_KeepsTheCardAttachedToItsAccount()
        {
            // The reason refs exist. Ids are regenerated on import, so a card carrying the old
            // account's Guid would arrive pointing at nothing — silently.
            await using var source = await CreateServiceAsync();
            var bank = await AddPwAsync(source, "banco.com");
            await source.AddCardEntryAsync(
                new CardEntry { CardholderName = "DEBIT", LinkedEntryId = bank.Id }, "4111111111111111", "123", "4821");

            var backup = await source.ExportBackupAsync();

            await using var target = await CreateOtherDeviceAsync();
            await target.ImportBackupAsync(backup);

            var account = Assert.Single(await target.GetEntriesAsync<ServiceEntry>());
            var card = Assert.Single(await target.GetEntriesAsync<CardEntry>());
            Assert.NotEqual(bank.Id, account.Id);          // genuinely a new id
            Assert.Equal(account.Id, card.LinkedEntryId);  // and the link followed it
        }

        [Fact]
        public async Task SeveralCardsOnOneAccount_AllArriveAttachedToIt()
        {
            await using var source = await CreateServiceAsync();
            var other = await AddPwAsync(source, "otro.com");
            var bank = await AddPwAsync(source, "banco.com");
            await source.AddCardEntryAsync(
                new CardEntry { CardholderName = "DEBIT", LinkedEntryId = bank.Id }, "4111", "123");
            await source.AddCardEntryAsync(
                new CardEntry { CardholderName = "CREDIT", LinkedEntryId = bank.Id }, "5555", "456");
            await source.AddCardEntryAsync(
                new CardEntry { CardholderName = "ELSEWHERE", LinkedEntryId = other.Id }, "6011", "789");

            await using var target = await CreateOtherDeviceAsync();
            await target.ImportBackupAsync(await source.ExportBackupAsync());

            var accounts = await target.GetEntriesAsync<ServiceEntry>();
            var newBank = accounts.Single(a => a.Site == "banco.com");
            var newOther = accounts.Single(a => a.Site == "otro.com");
            var cards = await target.GetEntriesAsync<CardEntry>();

            Assert.Equal(2, cards.Count(c => c.LinkedEntryId == newBank.Id));
            Assert.Single(cards.Where(c => c.LinkedEntryId == newOther.Id));
        }

        [Fact]
        public async Task ACardLinkedToNothing_StaysUnlinked()
        {
            await using var source = await CreateServiceAsync();
            await source.AddCardEntryAsync(new CardEntry { CardholderName = "LOOSE" }, "4111", "123");

            await using var target = await CreateOtherDeviceAsync();
            await target.ImportBackupAsync(await source.ExportBackupAsync());

            Assert.Null((await target.GetEntriesAsync<CardEntry>()).Single().LinkedEntryId);
        }

        [Fact]
        public async Task ARefNamingNoAccountInTheFile_IsDroppedRatherThanRestored()
        {
            // A link to nothing is worse than none: the card would claim a bank it has lost.
            await using var svc = await CreateServiceAsync();
            var backup = new VaultBackup
            {
                Cards = { new BackupCard { CardholderName = "ORPHAN", CardNumber = "4111", LinkedRef = 99 } },
            };

            await svc.ImportBackupAsync(backup);

            Assert.Null((await svc.GetEntriesAsync<CardEntry>()).Single().LinkedEntryId);
        }

        [Fact]
        public async Task ARoundTrip_KeepsMultipleAccountsOnOneSiteTogether()
        {
            // What the flat CSV shapes cannot do, and the reason this format exists.
            await using var source = await CreateServiceAsync();
            var entry = await AddPwAsync(source, "universidad.cr", "first");
            entry.Credentials.Add(new Credential
            {
                Label = "Matrícula",
                Fields = { new CredentialField
                {
                    Type = CredentialFieldType.Password, IsSecret = true,
                    SecretValue = source.EncryptValue("second"),
                } },
            });
            await source.UpdateEntryAsync(entry.Id, e => ((ServiceEntry)e).Credentials = entry.Credentials);

            await using var target = await CreateOtherDeviceAsync();
            await target.ImportBackupAsync(await source.ExportBackupAsync());

            var restored = Assert.Single(await target.GetEntriesAsync<ServiceEntry>());
            Assert.Equal(2, restored.Credentials.Count);
            Assert.Contains(restored.Credentials, c => c.Label == "Matrícula");
        }

        [Fact]
        public async Task ANoteSurvivesWithItsCriticalFlagAndTags()
        {
            await using var source = await CreateServiceAsync();
            await source.AddSecureNoteAsync(
                new SecureNote { Title = "Códigos", IsCritical = true, Tags = { "banco" } }, "1234-5678");

            await using var target = await CreateOtherDeviceAsync();
            await target.ImportBackupAsync(await source.ExportBackupAsync());

            var note = Assert.Single(await target.GetEntriesAsync<SecureNote>());
            Assert.Equal("Códigos", note.Title);
            Assert.True(note.IsCritical);
            Assert.Contains("banco", note.Tags);
            Assert.Equal("1234-5678", target.DecryptField(note.Content));
        }

        [Fact]
        public async Task SecretsAreReEncryptedForTheReceivingVault()
        {
            // Each vault has its own field key, so ciphertext cannot travel — the values move as
            // plaintext inside the file and are sealed again on arrival. The file's own
            // protection is the passphrase envelope wrapped around it.
            await using var source = await CreateServiceAsync();
            await AddPwAsync(source, "github.com", "s3cret");
            await source.AddCardEntryAsync(new CardEntry { CardholderName = "J" }, "4111", "123", "4821");

            await using var target = await CreateOtherDeviceAsync();
            await target.ImportBackupAsync(await source.ExportBackupAsync());

            var card = Assert.Single(await target.GetEntriesAsync<CardEntry>());
            Assert.Equal("4821", target.DecryptField(card.Pin!));
            var restored = Assert.Single(await target.GetEntriesAsync<ServiceEntry>());
            Assert.Equal("s3cret", target.DecryptSecret(PwField(restored)));
        }

        [Fact]
        public async Task AVersionOneBackup_StillImports()
        {
            // Files written before notes and cards existed must keep working.
            await using var svc = await CreateServiceAsync();
            var old = new VaultBackup
            {
                Version = 1,
                Services = { new BackupServiceEntry { Site = "old.com" } },
            };

            var added = await svc.ImportBackupAsync(old);

            Assert.Equal(1, added);
            Assert.Single(await svc.GetEntriesAsync<ServiceEntry>());
            Assert.Empty(await svc.GetEntriesAsync<SecureNote>());
        }

        [Fact]
        public async Task TheCountOfferedForConfirmation_IncludesNotesAndCards()
        {
            // This number is the whole basis of the user's consent before anything is written.
            await using var svc = await CreateServiceAsync();
            await AddPwAsync(svc, "a.com");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "n" }, "body");
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "c" }, "4111", "123");

            var result = new ImportResult { Backup = await svc.ExportBackupAsync() };

            Assert.Equal(3, result.EntryCount);
            Assert.Equal(1, result.ServiceCount);
            Assert.Equal(1, result.NoteCount);
            Assert.Equal(1, result.CardCount);
        }

        // ─── The Key field type ──────────────────────────────────────────────

        [Fact]
        public void KeyFieldsAreSecretByDefault()
        {
            // The whole point of the type: stored as Text, an API key sat unmasked and searchable.
            Assert.True(CredentialField.IsSecretByDefault(CredentialFieldType.Key));
            Assert.False(CredentialField.IsSecretByDefault(CredentialFieldType.Text));
        }

        [Fact]
        public void KeyKeepsItsStoredNumber()
        {
            // The enum persists as integers and has no string converter, so appending is the only
            // safe change. If this ever fails, vaults already on devices have been retyped.
            Assert.Equal(6, (int)CredentialFieldType.Text);
            Assert.Equal(7, (int)CredentialFieldType.Web);
            Assert.Equal(8, (int)CredentialFieldType.Key);
        }

        [Fact]
        public async Task KeyFieldIsEncryptedAndSurvivesARoundTrip()
        {
            await using var svc = await CreateServiceAsync();
            const string token = "sk-live-3f9a2b7c1d4e5f6a8b9c0d1e2f3a4b5c";
            await AddWithFieldAsync(svc, "api.example.com", CredentialFieldType.Key, token);

            var stored = (await svc.GetEntriesAsync<ServiceEntry>()).Single();
            var field = stored.Credentials[0].Fields[0];
            Assert.True(field.IsSecret);
            Assert.Empty(field.PlainValue);              // never in the clear
            Assert.Equal(token, svc.DecryptSecret(field));
        }

        [Fact]
        public async Task AuditVaultAsync_LeavesKeysAlone()
        {
            // The service issues them, so their strength is not the user's to fix, and each is
            // unique to whoever issued it — scoring them would only manufacture false alarms.
            await using var svc = await CreateServiceAsync();
            await AddWithFieldAsync(svc, "api.example.com", CredentialFieldType.Key, "abc123");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(0, report.TotalPasswords);
            Assert.Empty(report.Issues);
        }

        // ─── Card PINs in the audit ──────────────────────────────────────────

        [Fact]
        public async Task AuditVaultAsync_NeverCallsACardPinWeak()
        {
            // Four digits can never score well. Reporting every card as weak would bury the
            // findings the user can actually do something about, so PINs are compared but not
            // scored — the bank picks the length, not the user.
            await using var svc = await CreateServiceAsync();
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "JANE" }, "4111111111111111", "123", "1234");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(0, report.WeakCount);
            Assert.DoesNotContain(report.Issues, i => i.Type == AuditIssueType.WeakPassword);
        }

        [Fact]
        public async Task AuditVaultAsync_ReportsTheSamePinOnTwoCards()
        {
            // The finding that *is* actionable: change one of them.
            await using var svc = await CreateServiceAsync();
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "DEBIT" }, "4111111111111111", "123", "4821");
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "CREDIT" }, "5555444433332222", "456", "4821");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(2, report.ReusedCount);
            Assert.All(report.Issues, i => Assert.Equal(AuditIssueType.ReusedPassword, i.Type));
        }

        [Fact]
        public async Task AuditVaultAsync_LeavesDistinctPinsAlone()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "DEBIT" }, "4111111111111111", "123", "4821");
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "CREDIT" }, "5555444433332222", "456", "9137");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Empty(report.Issues);
            Assert.Equal(2, report.TotalPasswords);   // both were examined
        }

        [Fact]
        public async Task AuditVaultAsync_LabelsACardWithoutShowingItsNumber()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "JANE M DOE" }, "4111111111111111", "123", "4821");
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "JANE M DOE" }, "5555444433332222", "456", "4821");

            var report = await svc.AuditVaultAsync(NewAuditor());

            var label = report.Issues[0].EntryLabel;
            Assert.Contains("JANE M DOE", label);
            Assert.Contains("1111", label);                 // last four only
            Assert.DoesNotContain("4111111111111111", label);
            Assert.DoesNotContain("4821", label);           // never the PIN itself
        }

        [Fact]
        public async Task AuditVaultAsync_CountsCardsWithoutAPinAsNothingToCheck()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "NO PIN" }, "4111111111111111", "123");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(1, report.EntriesScanned);
            Assert.Equal(0, report.TotalPasswords);
            Assert.Equal(1, report.EntriesWithoutSecrets);
        }

        // ─── Changing a card's PIN from the account it belongs to ────────────

        [Fact]
        public async Task UpdateCardPinAsync_ChangesOnlyThePin()
        {
            await using var svc = await CreateServiceAsync();
            var account = await AddPwAsync(svc, "banco.com");
            var card = new CardEntry
            {
                CardholderName = "JANE M DOE", ExpiryMonth = 8, ExpiryYear = 2030,
                LinkedEntryId = account.Id,
            };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123", "4821");

            await svc.UpdateCardPinAsync(card.Id, "9137");

            var stored = (await svc.GetEntriesAsync<CardEntry>()).Single();
            Assert.Equal("9137", svc.DecryptField(stored.Pin!));
            // Everything else has to survive being edited from another screen.
            Assert.Equal("4111111111111111", svc.DecryptField(stored.CardNumber));
            Assert.Equal("123", svc.DecryptField(stored.Cvv));
            Assert.Equal(8, stored.ExpiryMonth);
            Assert.Equal(account.Id, stored.LinkedEntryId);
        }

        [Fact]
        public async Task UpdateCardPinAsync_WithNothing_RemovesThePin()
        {
            await using var svc = await CreateServiceAsync();
            var card = new CardEntry { CardholderName = "JANE" };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123", "4821");

            await svc.UpdateCardPinAsync(card.Id, "");

            Assert.Null((await svc.GetEntriesAsync<CardEntry>()).Single().Pin);
        }

        [Fact]
        public async Task GetCardsLinkedToAsync_ReturnsOnlyThatAccountsCards()
        {
            await using var svc = await CreateServiceAsync();
            var bank = await AddPwAsync(svc, "banco.com");
            var other = await AddPwAsync(svc, "otro.com");
            await svc.AddCardEntryAsync(
                new CardEntry { CardholderName = "DEBIT", LinkedEntryId = bank.Id }, "4111", "123", "1111");
            await svc.AddCardEntryAsync(
                new CardEntry { CardholderName = "CREDIT", LinkedEntryId = bank.Id }, "5555", "456", "2222");
            await svc.AddCardEntryAsync(
                new CardEntry { CardholderName = "ELSEWHERE", LinkedEntryId = other.Id }, "6011", "789", "3333");
            await svc.AddCardEntryAsync(
                new CardEntry { CardholderName = "LOOSE" }, "3782", "012", "4444");

            var linked = await svc.GetCardsLinkedToAsync(bank.Id);

            Assert.Equal(2, linked.Count);
            Assert.All(linked, c => Assert.Equal(bank.Id, c.LinkedEntryId));
        }

        // ─── Card PIN and its link to an account ─────────────────────────────

        [Fact]
        public async Task CardPin_IsEncryptedLikeEveryOtherSecret()
        {
            await using var svc = await CreateServiceAsync();
            var card = new CardEntry { CardholderName = "JANE M DOE" };

            await svc.AddCardEntryAsync(card, "4111111111111111", "123", "4821");

            var stored = (await svc.GetEntriesAsync<CardEntry>()).Single();
            Assert.NotNull(stored.Pin);
            Assert.Equal("4821", svc.DecryptField(stored.Pin!));
            // Never left lying in the clear anywhere on the entry.
            Assert.DoesNotContain("4821", System.Text.Json.JsonSerializer.Serialize(stored.Pin));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task CardWithoutAPin_StoresNullSoTheRowStaysHidden(string? pin)
        {
            // "Not set" has to stay distinguishable from "set to nothing": the detail sheet keys
            // the whole PIN row off null, and an empty EncryptedField would render an empty row
            // with a reveal button behind it.
            await using var svc = await CreateServiceAsync();

            await svc.AddCardEntryAsync(new CardEntry { CardholderName = "J" }, "4111", "123", pin);

            Assert.Null((await svc.GetEntriesAsync<CardEntry>()).Single().Pin);
        }

        [Fact]
        public async Task UpdateCardEntryAsync_CanSetAndThenClearThePin()
        {
            await using var svc = await CreateServiceAsync();
            var card = new CardEntry { CardholderName = "JANE M DOE" };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123", "4821");

            await svc.UpdateCardEntryAsync(card.Id, "JANE M DOE", 1, 2030, "4111111111111111", "123", "9999");
            Assert.Equal("9999", svc.DecryptField((await svc.GetEntriesAsync<CardEntry>()).Single().Pin!));

            // Clearing the box has to remove it, not silently keep the old PIN.
            await svc.UpdateCardEntryAsync(card.Id, "JANE M DOE", 1, 2030, "4111111111111111", "123", "");
            Assert.Null((await svc.GetEntriesAsync<CardEntry>()).Single().Pin);
        }

        [Fact]
        public async Task CardCanBeLinkedToAnAccountAndUnlinked()
        {
            await using var svc = await CreateServiceAsync();
            var account = await AddPwAsync(svc, "banco.com");
            var card = new CardEntry { CardholderName = "JANE M DOE", LinkedEntryId = account.Id };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123");

            Assert.Equal(account.Id, (await svc.GetEntriesAsync<CardEntry>()).Single().LinkedEntryId);

            await svc.UpdateCardEntryAsync(card.Id, "JANE M DOE", 1, 2030, "4111111111111111", "123", null, null);
            Assert.Null((await svc.GetEntriesAsync<CardEntry>()).Single().LinkedEntryId);
        }

        [Fact]
        public async Task SeveralCardsCanShareOneAccount()
        {
            // The case that motivated linking: one bank login, several pieces of plastic.
            await using var svc = await CreateServiceAsync();
            var account = await AddPwAsync(svc, "banco.com");

            await svc.AddCardEntryAsync(
                new CardEntry { CardholderName = "DEBIT", LinkedEntryId = account.Id }, "4111", "123");
            await svc.AddCardEntryAsync(
                new CardEntry { CardholderName = "CREDIT", LinkedEntryId = account.Id }, "5555", "456");

            var cards = await svc.GetEntriesAsync<CardEntry>();
            Assert.Equal(2, cards.Count);
            Assert.All(cards, c => Assert.Equal(account.Id, c.LinkedEntryId));
        }

        [Fact]
        public async Task DeletingTheAccount_LeavesTheCardIntactWithADanglingLink()
        {
            // Entries are a flat list, so nothing cascades. The card must survive — losing a card
            // because its account was tidied away would be far worse than a link pointing nowhere,
            // and the detail sheet says so rather than hiding the row.
            await using var svc = await CreateServiceAsync();
            var account = await AddPwAsync(svc, "banco.com");
            var card = new CardEntry { CardholderName = "JANE M DOE", LinkedEntryId = account.Id };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123", "4821");

            await svc.DeleteEntryAsync(account.Id);

            var stored = (await svc.GetEntriesAsync<CardEntry>()).Single();
            Assert.Equal(account.Id, stored.LinkedEntryId);
            Assert.Equal("4821", svc.DecryptField(stored.Pin!));
            Assert.DoesNotContain(await svc.GetEntriesAsync<ServiceEntry>(), e => e.Id == account.Id);
        }

        // ─── Card editing ────────────────────────────────────────────────────

        [Fact]
        public async Task UpdateCardEntryAsync_RewritesEveryFieldAndKeepsIdentity()
        {
            await using var svc = await CreateServiceAsync();
            var card = new CardEntry { CardholderName = "JANE M DOE", ExpiryMonth = 8, ExpiryYear = 2028 };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123");

            await svc.UpdateCardEntryAsync(card.Id, "JOHN Q PUBLIC", 11, 2030, "5555444433332222", "987");

            var stored = (await svc.GetEntriesAsync<CardEntry>()).Single();
            Assert.Equal(card.Id, stored.Id);              // same entry, not a delete-and-re-add
            Assert.Equal("JOHN Q PUBLIC", stored.CardholderName);
            Assert.Equal(11, stored.ExpiryMonth);
            Assert.Equal(2030, stored.ExpiryYear);
            Assert.Equal("5555444433332222", svc.DecryptField(stored.CardNumber));
            Assert.Equal("987", svc.DecryptField(stored.Cvv));
        }

        [Fact]
        public async Task UpdateCardEntryAsync_ReEncryptsRatherThanStoringPlaintext()
        {
            // The number and CVV are the whole point of the entry; an update path that forgot to
            // encrypt would leave them readable in the vault file.
            await using var svc = await CreateServiceAsync();
            var card = new CardEntry { CardholderName = "JANE M DOE", ExpiryMonth = 1, ExpiryYear = 2030 };
            await svc.AddCardEntryAsync(card, "4111111111111111", "123");

            await svc.UpdateCardEntryAsync(card.Id, "JANE M DOE", 1, 2030, "5555444433332222", "987");

            var stored = (await svc.GetEntriesAsync<CardEntry>()).Single();
            Assert.DoesNotContain("5555444433332222", stored.CardNumber.CipherText);
            Assert.DoesNotContain("987", stored.Cvv.CipherText);
        }

        // ─── Critical notes ──────────────────────────────────────────────────

        [Fact]
        public async Task SecureNote_CriticalFlag_RoundTrips()
        {
            await using var svc = await CreateServiceAsync();
            await svc.AddSecureNoteAsync(new SecureNote { Title = "Recovery codes", IsCritical = true }, "abc");
            await svc.AddSecureNoteAsync(new SecureNote { Title = "Shopping list" }, "milk");

            var notes = await svc.GetEntriesAsync<SecureNote>();

            Assert.True(notes.Single(n => n.Title == "Recovery codes").IsCritical);
            Assert.False(notes.Single(n => n.Title == "Shopping list").IsCritical);
        }

        [Fact]
        public void NoteWrittenBeforeTheCriticalFlagExisted_LoadsAsNotCritical()
        {
            // The flag is absent from every note already in a tester's vault, so the default has
            // to be the safe, quiet one rather than marking everything critical.
            const string json = """
            {"Id":"11111111-1111-1111-1111-111111111111","Title":"Old note",
             "Content":{"CipherText":"","Nonce":"","Tag":""},"Tags":[],"IsDeleted":false}
            """;

            var note = System.Text.Json.JsonSerializer.Deserialize<SecureNote>(json);

            Assert.NotNull(note);
            Assert.False(note!.IsCritical);
        }

        // ─── What the audit actually looks at ────────────────────────────────
        //
        // The auditor itself was covered; the projection that feeds it was not, and that is where
        // the gap lived — a tester reported the audit ignoring passwords they had typed by hand.

        private static PasswordManager.Core.Interfaces.IVaultAuditor NewAuditor() =>
            new PasswordManager.Infrastructure.Services.VaultAuditor(
                new PasswordManager.Infrastructure.Services.PasswordGenerator());

        private static async Task AddWithFieldAsync(
            PasswordManagerService svc, string site, CredentialFieldType type, string value)
        {
            var cred = new Credential();
            var secret = CredentialField.IsSecretByDefault(type);
            cred.Fields.Add(new CredentialField
            {
                Type = type,
                IsSecret = secret,
                PlainValue = secret ? string.Empty : value,
                SecretValue = secret ? svc.EncryptValue(value) : null,
            });
            await svc.AddServiceEntryAsync(new ServiceEntry { Site = site, Credentials = { cred } });
        }

        [Fact]
        public async Task AuditVaultAsync_ExaminesPinsAndNotOnlyPasswords()
        {
            // A PIN is a secret, carries a rotation policy, and being short is the likeliest thing
            // in the vault to be weak — yet it used to be skipped entirely.
            await using var svc = await CreateServiceAsync();
            await AddWithFieldAsync(svc, "bank.com", CredentialFieldType.Pin, "1234");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(1, report.TotalPasswords);
            Assert.Contains(report.Issues, i => i.Type == AuditIssueType.WeakPassword);
        }

        [Fact]
        public async Task AuditVaultAsync_CountsPasswordsAndPinsTogether()
        {
            await using var svc = await CreateServiceAsync();
            await AddWithFieldAsync(svc, "a.com", CredentialFieldType.Password, "Tr0ub4dor&3xample!");
            await AddWithFieldAsync(svc, "b.com", CredentialFieldType.Pin, "0000");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(2, report.TotalPasswords);
            Assert.Equal(2, report.EntriesScanned);
        }

        [Fact]
        public async Task AuditVaultAsync_LeavesTotpSecretsAlone()
        {
            // Machine-generated Base32: "weak" and "reused" are meaningless for it, and scoring it
            // would report every 2FA setup in the vault as a problem.
            await using var svc = await CreateServiceAsync();
            await AddWithFieldAsync(svc, "a.com", CredentialFieldType.TwoFactor, "JBSWY3DPEHPK3PXP");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(0, report.TotalPasswords);
            Assert.Empty(report.Issues);
        }

        [Fact]
        public async Task AuditVaultAsync_ReportsEntriesItCouldNotJudge()
        {
            // An entry holding only a plain text or e-mail field is neither healthy nor unhealthy.
            // Counting it silently as fine is how a vault reads "all good" while part of it was
            // never checked — so the count is surfaced instead.
            await using var svc = await CreateServiceAsync();
            await AddWithFieldAsync(svc, "has-pw.com", CredentialFieldType.Password, "Tr0ub4dor&3xample!");
            await AddWithFieldAsync(svc, "notes-only.com", CredentialFieldType.Text, "some note");
            await AddWithFieldAsync(svc, "email-only.com", CredentialFieldType.Email, "a@example.com");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(3, report.EntriesScanned);
            Assert.Equal(1, report.TotalPasswords);
            Assert.Equal(2, report.EntriesWithoutSecrets);
        }

        [Fact]
        public async Task AuditVaultAsync_SpotsTheSameSecretReusedAcrossEntries()
        {
            await using var svc = await CreateServiceAsync();
            await AddWithFieldAsync(svc, "a.com", CredentialFieldType.Password, "Tr0ub4dor&3xample!");
            await AddWithFieldAsync(svc, "b.com", CredentialFieldType.Password, "Tr0ub4dor&3xample!");

            var report = await svc.AuditVaultAsync(NewAuditor());

            Assert.Equal(2, report.ReusedCount);
        }

        // ─── Trash: delete, restore, purge ───────────────────────────────────
        //
        // Deleting was always a soft delete, but until now nothing in the app listed the trash or
        // restored from it — so this round trip had never been exercised end to end.

        [Fact]
        public async Task DeletedEntry_LeavesTheListButStaysInTheTrash()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "example.com");

            await svc.DeleteEntryAsync(entry.Id);

            Assert.Empty(await svc.GetEntriesAsync<ServiceEntry>());
            var trashed = Assert.Single(await svc.GetDeletedEntriesAsync());
            Assert.Equal(entry.Id, trashed.Id);
            Assert.NotNull(trashed.DeletedAt);
        }

        [Fact]
        public async Task RestoreEntryAsync_BringsItBackWithItsSecretIntact()
        {
            // Restoring has to return a usable entry, not just an visible one: the password must
            // still decrypt afterwards.
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "example.com", "s3cret-value");
            await svc.DeleteEntryAsync(entry.Id);

            await svc.RestoreEntryAsync(entry.Id);

            var restored = Assert.Single(await svc.GetEntriesAsync<ServiceEntry>());
            Assert.Equal(entry.Id, restored.Id);
            Assert.False(restored.IsDeleted);
            Assert.Null(restored.DeletedAt);
            Assert.Equal("s3cret-value", svc.DecryptSecret(PwField(restored)));
            Assert.Empty(await svc.GetDeletedEntriesAsync());
        }

        [Fact]
        public async Task PurgeDeletedAsync_RemovesOnlyWhatWasInTheTrash()
        {
            await using var svc = await CreateServiceAsync();
            var kept = await AddPwAsync(svc, "keep.com");
            var thrown = await AddPwAsync(svc, "throw.com");
            await svc.DeleteEntryAsync(thrown.Id);

            await svc.PurgeDeletedAsync();

            Assert.Empty(await svc.GetDeletedEntriesAsync());
            var remaining = Assert.Single(await svc.GetEntriesAsync<ServiceEntry>());
            Assert.Equal(kept.Id, remaining.Id);
        }

        [Fact]
        public async Task RestoreEntryAsync_OnSomethingNotInTheTrash_DoesNothing()
        {
            await using var svc = await CreateServiceAsync();
            var entry = await AddPwAsync(svc, "example.com");

            await svc.RestoreEntryAsync(entry.Id);          // never deleted
            await svc.RestoreEntryAsync(Guid.NewGuid());    // never existed

            Assert.Single(await svc.GetEntriesAsync<ServiceEntry>());
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
