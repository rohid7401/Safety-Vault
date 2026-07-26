namespace PasswordManager.UI.Abstractions
{
    /// <summary>
    /// Platform-neutral file/folder access. Implemented per shell:
    /// MAUI uses FilePicker / FolderPicker / FileSaver; a future web shell uses the
    /// browser file APIs. Stream-based methods are preferred on mobile, where pickers
    /// return content-URI streams rather than filesystem paths.
    /// </summary>
    public interface IFilePickerService
    {
        /// <summary>Picks an existing file and returns its path (may be a cached copy on mobile).</summary>
        Task<string?> PickFileAsync(string? filterTitle = null, string[]? extensions = null);

        /// <summary>Picks an existing file and returns a readable stream + display name.</summary>
        Task<PickedFile?> PickFileForReadAsync(string? filterTitle = null, string[]? extensions = null);

        /// <summary>
        /// Picks one or more existing files and returns a readable stream + display name for
        /// each. Used where a whole folder can't be picked (mobile — see
        /// <see cref="IPlatformInfo.HasFilesystemFolderAccess"/>): the user selects the files
        /// individually instead. Empty (not null) if the user cancels.
        /// </summary>
        Task<IReadOnlyList<PickedFile>> PickMultipleFilesForReadAsync(string? filterTitle = null, string[]? extensions = null);

        /// <summary>Picks an existing folder and returns its path.</summary>
        Task<string?> PickFolderAsync(string? title = null);

        /// <summary>Opens a "Save As" dialog seeded with optional bytes; returns the chosen path.</summary>
        Task<string?> SaveFileAsync(string suggestedFileName = "file.txt", byte[]? initialBytes = null);

        /// <summary>Saves a stream through a "Save As" dialog; returns the chosen path.</summary>
        Task<string?> SaveStreamAsync(string suggestedFileName, Stream content);
    }
}
