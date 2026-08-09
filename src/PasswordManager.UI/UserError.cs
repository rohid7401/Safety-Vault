using System.Diagnostics;
using PasswordManager.Core.Exceptions;
using PasswordManager.UI.Localization;

namespace PasswordManager.UI
{
    /// <summary>
    /// N4 — turns an exception into a message that is safe to show on screen, in the user's
    /// language. Failures we raise on purpose carry an <see cref="AppErrorCode"/> (see
    /// <see cref="ILocalizedError"/>) which is resolved against the active locale here.
    /// Everything else — IO errors carrying absolute paths, cryptographic exceptions, JSON
    /// parser text — collapses to one generic message, so the UI never leaks filesystem
    /// structure or internals. The technical detail goes to <see cref="Debug"/> instead.
    ///
    /// <para>Messages used to be read straight off <c>ex.Message</c>, which is why errors
    /// still appeared in English for Spanish users: those strings are authored in Core and
    /// Infrastructure, which have no locale and should not gain one. A code crosses that
    /// boundary; prose cannot.</para>
    /// </summary>
    public static class UserError
    {
        public static string Describe(Loc l, Exception ex)
        {
            Debug.WriteLine($"[SafetyVault] {ex.GetType().Name}: {ex}");

            // A code is both translatable and inherently safe: the sentence it maps to is one
            // we wrote, so it embeds no path or secret whatever threw it.
            if (ex is ILocalizedError localized)
                return l.Format(KeyFor(localized.Code), localized.Args);

            if (ex is GeneratorConstraintException)
                return l["error.generatorConflict"];

            return l["error.unexpected"];
        }

        private static string KeyFor(AppErrorCode code) => code switch
        {
            AppErrorCode.UsernameRequired => "error.usernameRequired",
            AppErrorCode.EmailRequired => "error.emailRequired",
            AppErrorCode.PassphraseTooShort => "error.passphraseTooShort",
            AppErrorCode.UsernameHasSpaces => "error.usernameHasSpaces",
            AppErrorCode.EmailHasSpaces => "error.emailHasSpaces",
            AppErrorCode.EmailInvalid => "error.emailInvalid",
            AppErrorCode.PassphrasePadded => "error.passphrasePadded",
            AppErrorCode.UsernameInvalid => "error.usernameInvalid",
            AppErrorCode.NoPgpIdentity => "error.noPgpIdentity",
            AppErrorCode.BackupPassphraseRequired => "error.backupPassphraseRequired",
            AppErrorCode.BackupNotRecognised => "error.backupNotRecognised",
            AppErrorCode.BackupCannotOpen => "error.backupCannotOpen",
            AppErrorCode.UsernameTaken => "error.usernameTaken",
            AppErrorCode.EmailTaken => "error.emailTaken",
            AppErrorCode.VaultFolderExists => "error.vaultFolderExists",
            AppErrorCode.BadCredentials => "error.badCredentials",

            AppErrorCode.KeyringUnreadable => "error.keyringUnreadable",
            AppErrorCode.KeyringCorrupt => "error.keyringCorrupt",
            AppErrorCode.UnsupportedKdf => "error.unsupportedKdf",

            AppErrorCode.NoBackupAvailable => "error.noBackupAvailable",
            AppErrorCode.VaultTruncated => "error.vaultTruncated",
            AppErrorCode.VaultCorrupt => "error.vaultCorrupt",
            AppErrorCode.VaultAuthenticationFailed => "error.vaultAuthFailed",

            AppErrorCode.NoPrivateKeyOrBadPassphrase => "error.noPrivateKeyOrBadPassphrase",
            AppErrorCode.NoEncryptionKeyInFile => "error.noEncryptionKeyInFile",
            AppErrorCode.NoPublicKeyInData => "error.noPublicKeyInData",

            AppErrorCode.NoFilesToBundle => "error.noFilesToBundle",
            AppErrorCode.NoColumnsSelected => "error.noColumnsSelected",
            AppErrorCode.PathEscapesKeyDirectory => "error.pathEscapesKeyDirectory",
            AppErrorCode.KeyServerUnreachable => "error.keyServerUnreachable",

            AppErrorCode.InvalidTotpSecret => "error.invalidTotpSecret",

            AppErrorCode.PasswordLengthTooShort => "error.passwordLengthTooShort",
            AppErrorCode.NoCharacterSetEnabled => "error.noCharacterSetEnabled",

            _ => "error.unexpected",
        };
    }
}
