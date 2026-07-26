namespace PasswordManager.UI.Abstractions
{
    /// <summary>
    /// The one platform fact the UI actually needs to branch on. Implemented per shell
    /// (MAUI uses DeviceInfo); a future web shell would report <c>false</c>.
    /// </summary>
    public interface IPlatformInfo
    {
        /// <summary>
        /// True where a folder picked by the user resolves to a real filesystem path that
        /// <see cref="System.IO.Directory"/>/<see cref="System.IO.File"/> can read and write
        /// directly (Windows, macOS). False where it only yields a content-URI-backed handle
        /// with no direct filesystem access (Android's Storage Access Framework, and iOS's
        /// security-scoped bookmarks) — there, folder-based flows must go through streams
        /// (single files, or a picked *list* of files) instead of <c>Directory</c> APIs.
        /// </summary>
        bool HasFilesystemFolderAccess { get; }
    }
}
