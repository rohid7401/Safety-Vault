using System.Security.Cryptography;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Core.Services
{
    public sealed class PasswordManagerService : IDisposable, IAsyncDisposable
    {
        private readonly IVaultRepository _repository;
        private readonly IAesService _aesService;

        private byte[]? _aesKey;
        private bool _disposed;

        private PasswordManagerService(
            IVaultRepository repository,
            IAesService aesService,
            byte[] fieldKey)
        {
            _repository = repository;
            _aesService = aesService;
            _aesKey = fieldKey;
        }

        /// <summary>
        /// Takes ownership of <paramref name="fieldKey"/> (zeroized on Dispose) — the caller
        /// derives it from the already-unlocked Vault Key (see VaultKeyRing.DeriveSubkey in
        /// the Infrastructure layer).
        /// </summary>
        public static Task<PasswordManagerService> CreateAsync(
            IVaultRepository repository,
            IAesService aesService,
            byte[] fieldKey)
        {
            return Task.FromResult(new PasswordManagerService(repository, aesService, fieldKey));
        }

        /// <summary>
        /// Writes the account's PGP key pair (used for encrypting files for contacts) back to
        /// disk if missing, using the copy stored inside the vault. This is what lets a vault
        /// copied to a new device — without its loose key files — become fully usable again
        /// once unlocked with just the passphrase.
        /// </summary>
        public async Task EnsurePgpKeyFilesAsync(string vaultFolder)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            var publicPath = Path.Combine(vaultFolder, "public_key.asc");
            var privatePath = Path.Combine(vaultFolder, "private_key.asc");

            if (!File.Exists(publicPath) && !string.IsNullOrEmpty(vault.PgpPublicKeyArmored))
                await File.WriteAllTextAsync(publicPath, vault.PgpPublicKeyArmored);
            if (!File.Exists(privatePath) && !string.IsNullOrEmpty(vault.PgpPrivateKeyArmored))
                await File.WriteAllTextAsync(privatePath, vault.PgpPrivateKeyArmored);
        }

        /// <summary>Every stored preference for this account. Absent keys are the caller's to
        /// default — the vault holds only what was actually chosen.</summary>
        public async Task<Dictionary<string, string>> GetSettingsAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return new Dictionary<string, string>(vault.Settings, StringComparer.Ordinal);
        }

        /// <summary>
        /// Writes preferences, merging rather than replacing: a build that does not know about a
        /// key must not erase it just by saving the ones it does know. A null value removes a key,
        /// which is how a preference returns to its default.
        /// </summary>
        public async Task SetSettingsAsync(IReadOnlyDictionary<string, string?> values)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            foreach (var (key, value) in values)
            {
                if (value is null) vault.Settings.Remove(key);
                else vault.Settings[key] = value;
            }

            await _repository.SaveAsync(vault);
        }

        /// <summary>
        /// The account's PGP identity, ready to be carried to another device.
        ///
        /// <para>Moving the identity is not the way to move a *backup* — a backup must open with
        /// something the user remembers, not with a file that can be lost alongside the phone.
        /// This exists for the other half: a key pair is who you are to the people who encrypt
        /// files for you, so replacing it on a new device makes everything already sent to the
        /// old one unreadable. The same key has to travel.</para>
        /// </summary>
        public async Task<PgpIdentity> ExportPgpIdentityAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            if (string.IsNullOrEmpty(vault.PgpPrivateKeyArmored))
                throw new LocalizedArgumentException(AppErrorCode.NoPgpIdentity);

            return new PgpIdentity(vault.PgpPublicKeyArmored ?? string.Empty, vault.PgpPrivateKeyArmored);
        }

        /// <summary>
        /// Adopts an identity exported from another device, re-sealing the private key under this
        /// account's passphrase so it behaves exactly like one generated here — otherwise it would
        /// keep demanding the passphrase of a device the user may no longer have.
        /// </summary>
        /// <param name="sourcePassphrase">The passphrase that protects the key as it arrives.</param>
        /// <param name="newPassphrase">This account's vault passphrase.</param>
        public async Task ImportPgpIdentityAsync(
            IPgpService pgpService, string vaultFolder, PgpIdentity identity,
            string sourcePassphrase, string newPassphrase)
        {
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(identity.PrivateKeyArmored))
                throw new LocalizedArgumentException(AppErrorCode.NoPgpIdentity);

            // Throws on a wrong source passphrase, before anything is overwritten.
            var rekeyed = pgpService.ChangePrivateKeyPassphrase(
                identity.PrivateKeyArmored, sourcePassphrase, newPassphrase);

            var vault = await _repository.LoadAsync();
            vault.PgpPublicKeyArmored = identity.PublicKeyArmored;
            vault.PgpPrivateKeyArmored = rekeyed;
            await _repository.SaveAsync(vault);

            // The files are what every PGP screen reads; the vault copy is what survives a
            // reinstall. Both have to agree.
            await File.WriteAllTextAsync(Path.Combine(vaultFolder, "public_key.asc"), identity.PublicKeyArmored);
            await File.WriteAllTextAsync(Path.Combine(vaultFolder, "private_key.asc"), rekeyed);
        }

        /// <summary>True once this account has generated the PGP identity used to encrypt
        /// files for contacts. Registration no longer creates one automatically — see
        /// <see cref="GenerateOwnPgpIdentityAsync"/> — so this is how a caller checks whether
        /// the on-demand prompt should be shown.</summary>
        public async Task<bool> HasOwnPgpIdentityAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return !string.IsNullOrEmpty(vault.PgpPublicKeyArmored);
        }

        /// <summary>
        /// Generates this account's PGP identity (an RSA-2048 key pair) the first time it is
        /// actually needed, rather than during registration: it is the slowest and most
        /// variable-duration part of what registration used to do, yet most accounts never use
        /// the file-encryption feature it exists for. <paramref name="passphrase"/> protects the
        /// private key armor and should be the caller's vault passphrase, re-entered for this
        /// call since it is never retained after login. <paramref name="userId"/> is embedded in
        /// the key (conventionally "Name &lt;email@example.com&gt;") — it must contain the
        /// account's real email, since that is what a keyserver search and the "is this the
        /// right key?" mismatch check both match against; a placeholder here would make the key
        /// unfindable by anyone searching for the owner's actual address. No-ops if an identity
        /// already exists.
        /// </summary>
        public async Task GenerateOwnPgpIdentityAsync(
            IPgpService pgpService, string vaultFolder, string passphrase, string userId)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            if (!string.IsNullOrEmpty(vault.PgpPublicKeyArmored)) return;

            var publicPath = Path.Combine(vaultFolder, "public_key.asc");
            var privatePath = Path.Combine(vaultFolder, "private_key.asc");

            // CPU-bound (prime search): off the calling thread so a UI caller stays responsive.
            await Task.Run(() => pgpService.GenerateKeyPair(publicPath, privatePath, passphrase, userId))
                .ConfigureAwait(false);

            vault.PgpPublicKeyArmored = await File.ReadAllTextAsync(publicPath);
            vault.PgpPrivateKeyArmored = await File.ReadAllTextAsync(privatePath);
            await _repository.SaveAsync(vault);
        }

        // ─── Query ───────────────────────────────────────────────────────────

        public async Task<List<VaultEntry>> GetAllEntriesAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.Where(e => !e.IsDeleted).ToList();
        }

        public async Task<List<T>> GetEntriesAsync<T>() where T : VaultEntry
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.OfType<T>().Where(e => !e.IsDeleted).ToList();
        }

        public async Task<VaultEntry?> GetEntryByIdAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.FirstOrDefault(e => e.Id == id && !e.IsDeleted);
        }

        public async Task<List<VaultEntry>> FindEntriesAsync(Func<VaultEntry, bool> predicate)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.Where(e => !e.IsDeleted && predicate(e)).ToList();
        }

        // ─── Add entries ─────────────────────────────────────────────────────

        public async Task AddSecureNoteAsync(SecureNote note, string plainContent)
        {
            ThrowIfDisposed();
            note.Content = EncryptField(plainContent);
            await AddEntryAsync(note);
        }

        public async Task AddCardEntryAsync(
            CardEntry card, string plainCardNumber, string plainCvv, string? plainPin = null)
        {
            ThrowIfDisposed();
            card.CardNumber = EncryptField(plainCardNumber);
            card.Cvv = EncryptField(plainCvv);
            card.Pin = EncryptOptional(plainPin);
            await AddEntryAsync(card);
        }

        /// <summary>Null for a blank PIN, so "not set" stays distinguishable from "set to
        /// nothing" — the detail sheet hides the row entirely in the first case.</summary>
        private EncryptedField? EncryptOptional(string? plain) =>
            string.IsNullOrWhiteSpace(plain) ? null : EncryptField(plain);

        /// <summary>
        /// Changes only a card's PIN, leaving its number, CVV and link untouched.
        ///
        /// <para>Exists so the PIN can be changed from the account it belongs to without that
        /// screen having to decrypt and re-save the whole card. The card remains the single place
        /// the PIN is stored — the account view edits it through this rather than keeping a copy,
        /// so the two can never drift apart.</para>
        /// </summary>
        public async Task UpdateCardPinAsync(Guid cardId, string? plainPin)
        {
            ThrowIfDisposed();
            await UpdateEntryAsync(cardId, e =>
            {
                if (e is CardEntry card) card.Pin = EncryptOptional(plainPin);
            });
        }

        /// <summary>Cards attached to the given account, for showing them alongside it.</summary>
        public async Task<List<CardEntry>> GetCardsLinkedToAsync(Guid entryId)
        {
            ThrowIfDisposed();
            var cards = await GetEntriesAsync<CardEntry>();
            return cards.Where(c => c.LinkedEntryId == entryId).ToList();
        }

        /// <summary>
        /// Rewrites a card in place, re-encrypting the number and CVV. Editing used to be
        /// impossible: the only way to correct a typo in a card number was to delete the entry
        /// and add it again, losing its history. Takes the plaintext because the caller has
        /// already decrypted it for the form.
        /// </summary>
        public async Task UpdateCardEntryAsync(
            Guid id, string cardholderName, int expiryMonth, int expiryYear,
            string plainCardNumber, string plainCvv,
            string? plainPin = null, Guid? linkedEntryId = null)
        {
            ThrowIfDisposed();
            await UpdateEntryAsync(id, e =>
            {
                if (e is not CardEntry card) return;
                card.CardholderName = cardholderName;
                card.ExpiryMonth = expiryMonth;
                card.ExpiryYear = expiryYear;
                card.CardNumber = EncryptField(plainCardNumber);
                card.Cvv = EncryptField(plainCvv);
                card.Pin = EncryptOptional(plainPin);
                card.LinkedEntryId = linkedEntryId;
            });
        }

        private async Task AddEntryAsync(VaultEntry entry)
        {
            entry.CreationTime = DateTime.UtcNow;
            entry.LastUpdateTime = DateTime.UtcNow;
            var vault = await _repository.LoadAsync();
            vault.Entries.Add(entry);
            await _repository.SaveAsync(vault);
        }

        // ─── Update ──────────────────────────────────────────────────────────

        public async Task UpdateEntryAsync(Guid id, Action<VaultEntry> updateAction)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null) return;

            updateAction(entry);
            entry.LastUpdateTime = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
        }

        /// <summary>
        /// Stars or unstars an entry, whatever kind it is.
        /// </summary>
        /// <remarks>
        /// Deliberately not routed through <see cref="UpdateEntryAsync"/>: that stamps
        /// LastUpdateTime, and starring is not a change to the secret. Letting it move the date
        /// would make "changed 2 minutes ago" mean "I tapped a heart", which is exactly the
        /// signal the rotation reminders and the audit read.
        /// </remarks>
        public async Task SetFavoriteAsync(Guid id, bool favorite)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null || entry.IsFavorite == favorite) return;

            entry.IsFavorite = favorite;
            await _repository.SaveAsync(vault);
        }

        // ─── Soft delete / Restore / Purge ───────────────────────────────────

        public async Task DeleteEntryAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id && !e.IsDeleted);
            if (entry is null) return;

            entry.IsDeleted = true;
            entry.DeletedAt = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
        }

        public async Task RestoreEntryAsync(Guid id)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var entry = vault.Entries.FirstOrDefault(e => e.Id == id && e.IsDeleted);
            if (entry is null) return;

            entry.IsDeleted = false;
            entry.DeletedAt = null;
            await _repository.SaveAsync(vault);
        }

        public async Task<List<VaultEntry>> GetDeletedEntriesAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.Where(e => e.IsDeleted).ToList();
        }

        public async Task PurgeDeletedAsync()
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            vault.Entries.RemoveAll(e => e.IsDeleted);
            await _repository.SaveAsync(vault);
        }

        /// <summary>
        /// Permanently removes trashed entries deleted longer ago than <paramref name="age"/>,
        /// returning how many went. Runs only when the user has asked for it — the trash keeps
        /// everything forever by default, because this deletes with no further confirmation.
        ///
        /// <para>An entry with no deletion date is left alone rather than treated as infinitely
        /// old: that field was added after the trash existed, so a missing one means "unknown",
        /// and guessing would quietly destroy the oldest things in there — exactly what someone
        /// would come looking for.</para>
        /// </summary>
        public async Task<int> PurgeDeletedOlderThanAsync(TimeSpan age)
        {
            ThrowIfDisposed();
            if (age <= TimeSpan.Zero) return 0;

            var cutoff = DateTime.UtcNow - age;
            var vault = await _repository.LoadAsync();
            var removed = vault.Entries.RemoveAll(
                e => e.IsDeleted && e.DeletedAt is DateTime when && when < cutoff);

            if (removed > 0) await _repository.SaveAsync(vault);
            return removed;
        }

        /// <summary>
        /// Permanently removes every entry of type <typeparamref name="T"/>, trashed ones
        /// included, and returns how many were removed. Deliberately a hard delete: this is
        /// the recovery path for a section that has become unusable (a bad import, thousands
        /// of junk rows), and moving those entries to the trash would leave the vault just
        /// as large. Nothing else is touched — the other sections and the PGP keys survive.
        /// </summary>
        public async Task<int> DeleteAllAsync<T>() where T : VaultEntry
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            var removed = vault.Entries.RemoveAll(e => e is T);
            if (removed > 0) await _repository.SaveAsync(vault);
            return removed;
        }

        /// <summary>Number of live (non-trashed) entries of the given type.</summary>
        public async Task<int> CountAsync<T>() where T : VaultEntry
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();
            return vault.Entries.Count(e => e is T && !e.IsDeleted);
        }

        // ─── Expiration ──────────────────────────────────────────────────────

        public async Task SetExpireTimeAsync(Guid id, DateTime? expireTime)
        {
            await UpdateEntryAsync(id, e => e.ExpireTime = expireTime);
        }

        // ─── Decrypt ─────────────────────────────────────────────────────────

        public string DecryptField(EncryptedField field)
        {
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(field.CipherText)) return string.Empty;
            return _aesService.Decrypt(field.CipherText, _aesKey!, field.Nonce, field.Tag);
        }

        // ─── Service entries (flexible credential model) ──────────────────────

        /// <summary>
        /// Encrypts a plaintext value into an <see cref="EncryptedField"/> for a secret
        /// credential field. The UI builds a <see cref="ServiceEntry"/>'s secret fields with
        /// this, then persists it via <see cref="AddServiceEntryAsync"/>.
        /// </summary>
        public EncryptedField EncryptValue(string plaintext)
        {
            ThrowIfDisposed();
            return EncryptField(plaintext);
        }

        /// <summary>Decrypts a secret field's current value (empty when it has none).</summary>
        public string DecryptSecret(CredentialField field)
        {
            ThrowIfDisposed();
            return field.SecretValue is null ? string.Empty : DecryptField(field.SecretValue);
        }

        /// <summary>Decrypts the single-slot previous value of a rotating field, or null if none.</summary>
        public string? DecryptPreviousSecret(CredentialField field)
        {
            ThrowIfDisposed();
            return field.PreviousSecret is null ? null : DecryptField(field.PreviousSecret);
        }

        /// <summary>Persists a new service entry (its secret fields already built via <see cref="EncryptValue"/>).</summary>
        public async Task AddServiceEntryAsync(ServiceEntry entry)
        {
            ThrowIfDisposed();
            await AddEntryAsync(entry);
        }

        /// <summary>
        /// Rotates a secret field: encrypts the new value, keeps the immediately-previous one
        /// (single slot) when the field has a rotation policy, restarts the rotation clock, and
        /// persists. Returns false when the entry/credential/field was not found.
        /// </summary>
        public async Task<bool> RotateFieldSecretAsync(Guid entryId, Guid credentialId, Guid fieldId, string newPlaintext)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            var entry = vault.Entries.OfType<ServiceEntry>().FirstOrDefault(e => e.Id == entryId && !e.IsDeleted);
            var cred = entry?.Credentials.FirstOrDefault(c => c.Id == credentialId);
            var field = cred?.Fields.FirstOrDefault(f => f.Id == fieldId);
            if (entry is null || cred is null || field is null) return false;

            field.SetSecret(EncryptField(newPlaintext));
            cred.LastUpdateTime = DateTime.UtcNow;
            entry.LastUpdateTime = DateTime.UtcNow;
            await _repository.SaveAsync(vault);
            return true;
        }

        // ─── Export / Import (flat portable shape) ────────────────────────────

        /// <summary>
        /// Flattens every <see cref="ServiceEntry"/> credential into a portable row (one row per
        /// credential). The portable/CSV shape is intentionally flat — email, username, the first
        /// password and the first 2FA secret — so it interops with other managers; richer fields
        /// (PIN, phone, extra passwords) are not represented in a plaintext export.
        /// </summary>
        public async Task<List<PortableEntry>> ExportEntriesAsync()
        {
            ThrowIfDisposed();
            var services = await GetEntriesAsync<ServiceEntry>();

            var list = new List<PortableEntry>();
            foreach (var svc in services)
            {
                foreach (var cred in svc.Credentials)
                {
                    list.Add(new PortableEntry
                    {
                        Site = svc.Site,
                        Username = FirstPlain(cred, CredentialFieldType.Username),
                        Email = FirstPlain(cred, CredentialFieldType.Email),
                        Password = FirstSecret(cred, CredentialFieldType.Password),
                        TotpSecret = FirstSecretOrNull(cred, CredentialFieldType.TwoFactor),
                        Tags = new List<string>(svc.Tags),
                    });
                }
            }
            return list;
        }

        /// <summary>
        /// Imports portable rows (CSV / Bitwarden, including exports from the older
        /// PasswordEntry-based versions) as <see cref="ServiceEntry"/>s — one entry with a single
        /// credential per row, mapping email/username to clear fields and password/2FA to secrets.
        /// </summary>
        public async Task ImportEntriesAsync(IReadOnlyList<PortableEntry> portableEntries)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            foreach (var portable in portableEntries)
            {
                var cred = new Credential { Label = portable.CredentialLabel };

                if (!string.IsNullOrEmpty(portable.Email))
                    cred.Fields.Add(PlainField(CredentialFieldType.Email, portable.Email));
                if (!string.IsNullOrEmpty(portable.Username))
                    cred.Fields.Add(PlainField(CredentialFieldType.Username, portable.Username));

                // Only when it says something the card title doesn't already — the importer falls
                // back to using the url as the site name, and repeating it on the credential
                // would show every imported card its own address twice.
                if (!string.IsNullOrEmpty(portable.Web) &&
                    !string.Equals(portable.Web, portable.Site, StringComparison.OrdinalIgnoreCase))
                    cred.Fields.Add(PlainField(CredentialFieldType.Web, portable.Web));

                cred.Fields.Add(SecretField(CredentialFieldType.Password, portable.Password));

                if (!string.IsNullOrEmpty(portable.TotpSecret))
                    cred.Fields.Add(SecretField(CredentialFieldType.TwoFactor, portable.TotpSecret));

                // The source's notes column has no typed equivalent, so it lands as free text
                // rather than being dropped — most managers put real information in there.
                if (!string.IsNullOrWhiteSpace(portable.Notes))
                    cred.Fields.Add(PlainField(CredentialFieldType.Text, portable.Notes));

                var entry = new ServiceEntry
                {
                    Site = portable.Site,
                    Tags = new List<string>(portable.Tags),
                    Credentials = { cred },
                    CreationTime = DateTime.UtcNow,
                    LastUpdateTime = DateTime.UtcNow,
                };

                vault.Entries.Add(entry);
            }

            await _repository.SaveAsync(vault);
        }

        // ─── Export / Import (native backup: full detail) ─────────────────────

        /// <summary>
        /// Builds a lossless <see cref="VaultBackup"/> of every service entry, decrypting each
        /// secret on the way out. The result holds plaintext — see the remarks on
        /// <see cref="VaultBackup"/> for why it cannot carry the stored ciphertexts instead, and
        /// why the caller is expected to wrap it in PGP before it touches disk.
        /// </summary>
        public async Task<VaultBackup> ExportBackupAsync()
        {
            ThrowIfDisposed();
            var services = await GetEntriesAsync<ServiceEntry>();
            var vaultForSettings = await _repository.LoadAsync();

            var backup = new VaultBackup { ExportedAt = DateTime.UtcNow };

            // Maps each account to the number cards will use to point at it. Local to the file:
            // real ids are regenerated on import, so carrying them across would only break.
            var refs = new Dictionary<Guid, int>();
            var nextRef = 1;

            foreach (var svc in services)
            {
                refs[svc.Id] = nextRef;
                var entry = new BackupServiceEntry
                {
                    Ref = nextRef++,
                    Site = svc.Site,
                    Tags = new List<string>(svc.Tags),
                    Grouped = svc.Grouped,
                    IsFavorite = svc.IsFavorite,
                    ExpireTime = svc.ExpireTime,
                    CreationTime = svc.CreationTime,
                    LastUpdateTime = svc.LastUpdateTime,
                };

                foreach (var cred in svc.Credentials)
                {
                    var credential = new BackupCredential
                    {
                        Label = cred.Label,
                        CreationTime = cred.CreationTime,
                        LastUpdateTime = cred.LastUpdateTime,
                    };

                    foreach (var field in cred.Fields)
                    {
                        credential.Fields.Add(new BackupField
                        {
                            Type = field.Type,
                            Label = field.Label,
                            IsSecret = field.IsSecret,
                            Value = field.IsSecret ? DecryptSecret(field) : field.PlainValue,
                            LastChanged = field.LastChanged,
                            TwoFactorKind = field.TwoFactorKind,
                            HotpCounter = field.HotpCounter,
                            Rotation = field.Rotation is null ? null : new BackupRotation
                            {
                                Interval = field.Rotation.Interval,
                                Unit = field.Rotation.Unit,
                                LastChanged = field.Rotation.LastChanged,
                            },
                        });
                    }

                    entry.Credentials.Add(credential);
                }

                backup.Services.Add(entry);
            }

            foreach (var note in await GetEntriesAsync<SecureNote>())
            {
                backup.Notes.Add(new BackupNote
                {
                    Title = note.Title,
                    Content = DecryptField(note.Content),
                    Tags = new List<string>(note.Tags),
                    IsCritical = note.IsCritical,
                    IsFavorite = note.IsFavorite,
                    CreationTime = note.CreationTime,
                    LastUpdateTime = note.LastUpdateTime,
                });
            }

            foreach (var card in await GetEntriesAsync<CardEntry>())
            {
                backup.Cards.Add(new BackupCard
                {
                    CardholderName = card.CardholderName,
                    CardNumber = DecryptField(card.CardNumber),
                    Cvv = DecryptField(card.Cvv),
                    Pin = card.Pin is null ? null : DecryptField(card.Pin),
                    ExpiryMonth = card.ExpiryMonth,
                    ExpiryYear = card.ExpiryYear,
                    IsFavorite = card.IsFavorite,
                    // Only if the account travels in this same file; a link to something left
                    // behind would arrive pointing at nothing.
                    LinkedRef = card.LinkedEntryId is Guid id && refs.TryGetValue(id, out var r) ? r : null,
                    CreationTime = card.CreationTime,
                    LastUpdateTime = card.LastUpdateTime,
                });
            }

            // Preferences travel too: restoring on a new device should hand back the app the user
            // had, not a default one they have to configure again.
            backup.Settings = new Dictionary<string, string>(vaultForSettings.Settings, StringComparer.Ordinal);

            return backup;
        }

        /// <summary>
        /// Restores a <see cref="VaultBackup"/>, re-encrypting every secret with *this* vault's
        /// field key. Entries are added, never merged: ids are regenerated, so importing the
        /// same backup twice yields duplicates rather than silently overwriting anything the
        /// user has changed since. Returns how many service entries were added.
        /// </summary>
        public async Task<int> ImportBackupAsync(VaultBackup backup)
        {
            ThrowIfDisposed();
            var vault = await _repository.LoadAsync();

            // File-local reference → the id this import assigns. Built while the accounts are
            // created, then used to reconnect the cards that pointed at them.
            var newIds = new Dictionary<int, Guid>();

            foreach (var source in backup.Services)
            {
                var entry = new ServiceEntry
                {
                    Site = source.Site,
                    Tags = new List<string>(source.Tags),
                    Grouped = source.Grouped,
                    IsFavorite = source.IsFavorite,
                    ExpireTime = source.ExpireTime,
                    CreationTime = source.CreationTime,
                    LastUpdateTime = DateTime.UtcNow,
                };

                foreach (var sourceCred in source.Credentials)
                {
                    var cred = new Credential
                    {
                        Label = sourceCred.Label,
                        CreationTime = sourceCred.CreationTime,
                        LastUpdateTime = DateTime.UtcNow,
                    };

                    foreach (var sourceField in sourceCred.Fields)
                    {
                        cred.Fields.Add(new CredentialField
                        {
                            Type = sourceField.Type,
                            Label = sourceField.Label,
                            IsSecret = sourceField.IsSecret,
                            PlainValue = sourceField.IsSecret ? string.Empty : sourceField.Value,
                            SecretValue = sourceField.IsSecret ? EncryptField(sourceField.Value) : null,
                            LastChanged = sourceField.LastChanged,
                            TwoFactorKind = sourceField.TwoFactorKind,
                            HotpCounter = sourceField.HotpCounter,
                            Rotation = sourceField.Rotation is null ? null : new RotationPolicy
                            {
                                Interval = sourceField.Rotation.Interval,
                                Unit = sourceField.Rotation.Unit,
                                LastChanged = sourceField.Rotation.LastChanged,
                            },
                        });
                    }

                    entry.Credentials.Add(cred);
                }

                vault.Entries.Add(entry);
                // What the file called this account, against the id it has just been given.
                if (source.Ref != 0) newIds[source.Ref] = entry.Id;
            }

            foreach (var note in backup.Notes)
            {
                vault.Entries.Add(new SecureNote
                {
                    Title = note.Title,
                    Content = EncryptField(note.Content),
                    Tags = new List<string>(note.Tags),
                    IsCritical = note.IsCritical,
                    IsFavorite = note.IsFavorite,
                    CreationTime = note.CreationTime,
                    LastUpdateTime = DateTime.UtcNow,
                });
            }

            foreach (var card in backup.Cards)
            {
                vault.Entries.Add(new CardEntry
                {
                    CardholderName = card.CardholderName,
                    CardNumber = EncryptField(card.CardNumber),
                    Cvv = EncryptField(card.Cvv),
                    Pin = string.IsNullOrWhiteSpace(card.Pin) ? null : EncryptField(card.Pin),
                    ExpiryMonth = card.ExpiryMonth,
                    ExpiryYear = card.ExpiryYear,
                    IsFavorite = card.IsFavorite,
                    // A reference naming no account in this file is dropped: a link pointing at
                    // nothing is worse than none, because the card would claim a bank it has lost.
                    LinkedEntryId = card.LinkedRef is int r && newIds.TryGetValue(r, out var id)
                        ? id
                        : null,
                    CreationTime = card.CreationTime,
                    LastUpdateTime = DateTime.UtcNow,
                });
            }

            // Merged, not replaced: a preference this build does not recognise stays, and one the
            // user has already set on this device is not overwritten by an older file.
            foreach (var (key, value) in backup.Settings)
                vault.Settings[key] = value;

            await _repository.SaveAsync(vault);
            return backup.Services.Count + backup.Notes.Count + backup.Cards.Count;
        }

        // ─── Export (interop rows) ────────────────────────────────────────────

        /// <summary>
        /// Flattens the vault to one <see cref="ExportRow"/> per credential — the shape a
        /// spreadsheet or another password manager expects. Carries more than
        /// <see cref="ExportEntriesAsync"/> (credential label, PIN, phone, free text) so the
        /// caller can pick which of it actually leaves the device.
        /// </summary>
        public async Task<List<ExportRow>> ExportRowsAsync()
        {
            ThrowIfDisposed();
            var services = await GetEntriesAsync<ServiceEntry>();

            var rows = new List<ExportRow>();
            foreach (var svc in services)
            {
                foreach (var cred in svc.Credentials)
                {
                    rows.Add(new ExportRow
                    {
                        Site = svc.Site,
                        CredentialLabel = cred.Label,
                        Username = FirstPlain(cred, CredentialFieldType.Username),
                        Email = FirstPlain(cred, CredentialFieldType.Email),
                        Phone = FirstPlain(cred, CredentialFieldType.Phone),
                        Web = FirstPlain(cred, CredentialFieldType.Web),
                        Password = FirstSecret(cred, CredentialFieldType.Password),
                        Pin = FirstSecret(cred, CredentialFieldType.Pin),
                        TotpSecret = FirstSecret(cred, CredentialFieldType.TwoFactor),
                        Text = JoinTextFields(cred),
                        Tags = string.Join(";", svc.Tags),
                    });
                }
            }
            return rows;
        }

        /// <summary>
        /// Free-text fields collapsed into one notes cell, labelled where the user named them,
        /// since no target format has a column per custom field.
        /// </summary>
        private string JoinTextFields(Credential cred)
        {
            var parts = cred.Fields
                .Where(f => f.Type == CredentialFieldType.Text)
                .Select(f =>
                {
                    var value = f.IsSecret ? DecryptSecret(f) : f.PlainValue;
                    return string.IsNullOrEmpty(f.Label) ? value : $"{f.Label}: {value}";
                })
                .Where(v => !string.IsNullOrWhiteSpace(v));

            return string.Join(" | ", parts);
        }

        // ─── Audit ───────────────────────────────────────────────────────────

        /// <summary>Secret types the audit can meaningfully judge.</summary>
        /// <remarks>
        /// PINs belong here: they are secrets, they carry rotation policies, and being short they
        /// are the likeliest thing in the vault to be weak or reused — yet they were skipped.
        /// TOTP secrets deliberately do not: they are machine-generated Base32, so "weak" and
        /// "reused" mean nothing for them and every one would be reported as a false alarm.
        /// API keys are excluded for the same reason — the service issues them, so their strength
        /// is not the user's to fix, and each one is unique to the service that issued it.
        /// </remarks>
        private static bool IsAuditable(CredentialField f) =>
            f.Type is CredentialFieldType.Password or CredentialFieldType.Pin;

        /// <summary>
        /// Audits every password and PIN across all service entries. Each becomes an
        /// <see cref="AuditItem"/> (decrypted here), with its expiry resolved from the field's
        /// rotation policy or, failing that, the entry-level expiry. The report also carries how
        /// much was read, so the UI can show coverage rather than only findings.
        /// </summary>
        public async Task<AuditReport> AuditVaultAsync(IVaultAuditor auditor)
        {
            ThrowIfDisposed();
            var services = await GetEntriesAsync<ServiceEntry>();

            var items = new List<AuditItem>();
            var withoutSecrets = 0;

            foreach (var svc in services)
            {
                var before = items.Count;
                foreach (var cred in svc.Credentials)
                {
                    foreach (var field in cred.Fields.Where(IsAuditable))
                    {
                        items.Add(new AuditItem
                        {
                            EntryId = svc.Id,
                            Label = AuditLabel(svc, cred),
                            Password = DecryptSecret(field),
                            ExpiresAt = field.Rotation?.ExpiresAt ?? svc.ExpireTime,
                        });
                    }
                }
                if (items.Count == before) withoutSecrets++;
            }

            // Card PINs join the comparison but are never scored for strength: four digits cannot
            // be made strong, so flagging each one would bury the findings that can be acted on.
            // Two cards sharing a PIN, on the other hand, is worth knowing and easy to fix.
            var cards = await GetEntriesAsync<CardEntry>();
            foreach (var card in cards)
            {
                if (card.Pin is null) { withoutSecrets++; continue; }

                items.Add(new AuditItem
                {
                    EntryId = card.Id,
                    Label = CardAuditLabel(card),
                    Password = DecryptField(card.Pin),
                    ExpiresAt = null,
                    StrengthChecked = false,
                });
            }

            var report = auditor.Audit(items);
            report.EntriesScanned = services.Count + cards.Count;
            report.EntriesWithoutSecrets = withoutSecrets;
            return report;
        }

        /// <summary>Names a card without exposing it: the holder plus the last four digits, the
        /// same shorthand the cards list uses.</summary>
        private string CardAuditLabel(CardEntry card)
        {
            var name = string.IsNullOrWhiteSpace(card.CardholderName) ? "•••" : card.CardholderName;
            try
            {
                var digits = new string(DecryptField(card.CardNumber).Where(char.IsDigit).ToArray());
                return digits.Length >= 4 ? $"{name} ···· {digits[^4..]}" : name;
            }
            catch
            {
                return name;
            }
        }

        private static string AuditLabel(ServiceEntry svc, Credential cred) =>
            string.IsNullOrEmpty(cred.Label) ? svc.Site : $"{svc.Site} · {cred.Label}";

        private static string FirstPlain(Credential cred, CredentialFieldType type) =>
            cred.Fields.FirstOrDefault(f => f.Type == type && !f.IsSecret)?.PlainValue ?? string.Empty;

        private string FirstSecret(Credential cred, CredentialFieldType type)
        {
            var field = cred.Fields.FirstOrDefault(f => f.Type == type && f.IsSecret);
            return field is null ? string.Empty : DecryptSecret(field);
        }

        private string? FirstSecretOrNull(Credential cred, CredentialFieldType type)
        {
            var value = FirstSecret(cred, type);
            return string.IsNullOrEmpty(value) ? null : value;
        }

        private CredentialField PlainField(CredentialFieldType type, string value) => new()
        {
            Type = type,
            IsSecret = false,
            PlainValue = value,
        };

        private CredentialField SecretField(CredentialFieldType type, string plaintext) => new()
        {
            Type = type,
            IsSecret = true,
            SecretValue = EncryptField(plaintext),
        };

        // ─── Vault integrity / recovery ──────────────────────────────────────

        /// <summary>
        /// Forces a verified load of the vault. Throws
        /// <see cref="Exceptions.VaultIntegrityException"/> if the vault has been
        /// tampered with or is corrupt. Call this right after unlocking.
        /// </summary>
        public async Task ValidateVaultAsync()
        {
            ThrowIfDisposed();
            await _repository.LoadAsync();
        }

        /// <summary>True if a known-good backup exists to restore from.</summary>
        public bool HasVaultBackup()
        {
            ThrowIfDisposed();
            return _repository.HasBackup();
        }

        /// <summary>Restores the vault from the last known-good backup and verifies it.</summary>
        public async Task RestoreVaultFromBackupAsync()
        {
            ThrowIfDisposed();
            await _repository.RestoreFromBackupAsync();
        }

        // ─── Helpers ─────────────────────────────────────────────────────────

        private EncryptedField EncryptField(string plainText)
        {
            var (cipher, nonce, tag) = _aesService.Encrypt(plainText, _aesKey!);
            return new EncryptedField { CipherText = cipher, Nonce = nonce, Tag = tag };
        }

        // ─── IDisposable ─────────────────────────────────────────────────────

        public void Dispose()
        {
            if (_disposed) return;
            if (_aesKey is not null)
            {
                CryptographicOperations.ZeroMemory(_aesKey);
                _aesKey = null;
            }
            // Zeroize any derived key material held by the repository (e.g. the blob key).
            (_repository as IDisposable)?.Dispose();
            _disposed = true;
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(PasswordManagerService));
        }
    }
}
