using System.Text;
using CommunityToolkit.Maui.Storage;
using FilePicker = Microsoft.Maui.Storage.FilePicker;

namespace PasswordManager.App.Services
{
    /// <summary>
    /// Wraps the native FilePicker (existing file), FolderPicker (existing folder),
    /// and FileSaver (new file) so Blazor components can use them uniformly.
    /// </summary>
    public class FileSystemPicker
    {
        public async Task<string?> PickFileAsync(string? filterTitle = null, string[]? extensions = null)
        {
            try
            {
                var options = new PickOptions
                {
                    PickerTitle = filterTitle ?? "Select a file",
                };

                if (extensions is { Length: > 0 })
                {
                    options.FileTypes = new FilePickerFileType(
                        new Dictionary<DevicePlatform, IEnumerable<string>>
                        {
                            { DevicePlatform.WinUI, extensions },
                            { DevicePlatform.macOS, extensions },
                            { DevicePlatform.iOS, extensions },
                            { DevicePlatform.Android, extensions },
                        });
                }

                var result = await FilePicker.Default.PickAsync(options);
                return result?.FullPath;
            }
            catch
            {
                return null;
            }
        }

        public async Task<string?> PickFolderAsync(string? title = null)
        {
            try
            {
                var result = await FolderPicker.Default.PickAsync(default);
                return result.IsSuccessful ? result.Folder?.Path : null;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Opens a "Save As" dialog and returns the path the user chose.
        /// FileSaver requires a real stream, so we pass an empty placeholder
        /// that the caller will overwrite when they actually produce data.
        /// </summary>
        public async Task<string?> SaveFileAsync(string suggestedFileName = "file.txt", byte[]? initialBytes = null)
        {
            try
            {
                var bytes = initialBytes ?? Encoding.UTF8.GetBytes(string.Empty);
                using var stream = new MemoryStream(bytes);
                var result = await FileSaver.Default.SaveAsync(suggestedFileName, stream, CancellationToken.None);
                return result.IsSuccessful ? result.FilePath : null;
            }
            catch
            {
                return null;
            }
        }
    }
}
