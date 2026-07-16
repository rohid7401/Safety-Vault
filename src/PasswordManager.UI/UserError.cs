using System.Diagnostics;
using PasswordManager.Core.Exceptions;
using PasswordManager.UI.Localization;

namespace PasswordManager.UI
{
    /// <summary>
    /// N4 — turns an exception into a message that is safe to show on screen. Our own
    /// controlled, user-facing exceptions (validation, generator conflicts, vault integrity)
    /// keep their message; everything else — IO errors carrying absolute paths, cryptographic
    /// exceptions, JSON parser text, etc. — is collapsed to a single generic message so the UI
    /// never leaks filesystem structure or internals. The full technical detail is written to
    /// <see cref="Debug"/> for developers instead of the screen.
    /// </summary>
    public static class UserError
    {
        public static string Describe(Loc l, Exception ex)
        {
            Debug.WriteLine($"[SecureVault] {ex.GetType().Name}: {ex}");
            return IsSafeToShow(ex) ? ex.Message : l["error.unexpected"];
        }

        // Only exception types whose messages we author ourselves (and that never embed paths
        // or secrets) are shown verbatim. Notably absent: UnauthorizedAccessException and
        // IOException / FileNotFoundException, whose messages can include absolute paths.
        private static bool IsSafeToShow(Exception ex) => ex is
            ArgumentException or
            InvalidOperationException or
            VaultIntegrityException or
            GeneratorConstraintException;
    }
}
