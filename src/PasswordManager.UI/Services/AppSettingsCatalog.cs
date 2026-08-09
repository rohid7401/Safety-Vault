using PasswordManager.Core.Models;

namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Every preference the app understands, in one place.
    ///
    /// <para>The defaults here are the app's opinion, not a historical accident: a value stored
    /// only because it happened to be the default would freeze it, so <see cref="AppSettings"/>
    /// clears a setting rather than writing one that matches. Changing a default therefore reaches
    /// everyone who never expressed a preference.</para>
    ///
    /// <para>The allowed values are listed alongside each setting. They are a short list rather
    /// than a free number for two reasons: a text box invites "0" for a timeout that must never be
    /// zero, and a fixed set is what the screen renders.</para>
    /// </summary>
    public static class AppSettingsCatalog
    {
        /// <summary>
        /// How long a copied secret stays on the clipboard. Two minutes by default — thirty
        /// seconds ran out before people had switched apps and pasted, so they copied again and
        /// left more copies behind rather than fewer.
        /// </summary>
        public static readonly Setting<int> ClipboardClearSeconds =
            Setting<int>.ForInt("clipboard.clearSeconds", 120);

        public static readonly int[] ClipboardChoices = { 30, 60, 120, 300 };

        /// <summary>
        /// How long the app may sit in the background before the vault locks itself.
        ///
        /// <para>There is deliberately no "never". A phone left on a table is the threat this
        /// exists for, and a preference that switches the protection off entirely would be chosen
        /// once, on a laptop, and then forgotten about on the phone. Five minutes is the longest
        /// offered.</para>
        /// </summary>
        public static readonly Setting<int> AutoLockGraceSeconds =
            Setting<int>.ForInt("autolock.graceSeconds", 30);

        public static readonly int[] AutoLockChoices = { 0, 30, 60, 300 };

        /// <summary>
        /// The rotation interval a new password field starts with. Only the starting value —
        /// every field still keeps whatever it was given.
        /// </summary>
        public static readonly Setting<int> RotationDefaultDays =
            Setting<int>.ForInt("rotation.defaultDays", 90);

        public static readonly int[] RotationChoices = { 30, 60, 90, 180, 365 };

        /// <summary>
        /// How long the trash keeps something before deleting it for good. Zero means never, and
        /// is the default: the trash has always kept everything, and switching that on by itself
        /// would destroy data on people who never asked for it. Emptying is irreversible and gets
        /// no second confirmation once armed, so opting in has to be a deliberate act.
        /// </summary>
        public static readonly Setting<int> TrashRetentionDays =
            Setting<int>.ForInt("trash.retentionDays", 0);

        public static readonly int[] TrashRetentionChoices = { 0, 30, 90, 365 };

        /// <summary>The export format the screen opens on. Purely where the picker starts.</summary>
        public static readonly Setting<ExportTarget> ExportDefaultTarget =
            Setting<ExportTarget>.ForEnum("export.target", ExportTarget.NativeBackup);

        /// <summary>
        /// The protection the export screen opens on.
        ///
        /// <para>Only the two protected modes can be stored. "Not encrypted" stays a per-export
        /// choice with its own warning: as a remembered default it would be picked once, for one
        /// good reason, and then silently apply to every backup afterwards — including the ones
        /// written years later by someone who has forgotten they chose it.</para>
        /// </summary>
        public static readonly Setting<ExportProtection> ExportDefaultProtection =
            Setting<ExportProtection>.ForEnum("export.protection", ExportProtection.Passphrase);

        /// <summary>
        /// Which identifier a brand-new account starts with. Both are non-secret identity fields,
        /// so neither choice can weaken anything.
        /// </summary>
        public static readonly Setting<CredentialFieldType> NewAccountField =
            Setting<CredentialFieldType>.ForEnum("entry.defaultField", CredentialFieldType.Email);

        public static readonly CredentialFieldType[] NewAccountFieldChoices =
            { CredentialFieldType.Email, CredentialFieldType.Username };
    }

    /// <summary>How an export is protected. Mirrors the modes the export screen offers.</summary>
    public enum ExportProtection
    {
        /// <summary>Sealed with a passphrase; opens on any device.</summary>
        Passphrase,

        /// <summary>Encrypted to this device's PGP key; opens only here.</summary>
        Pgp,
    }
}
