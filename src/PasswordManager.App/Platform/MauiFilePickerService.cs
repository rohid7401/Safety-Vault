using CommunityToolkit.Maui.Storage;
using PasswordManager.UI.Abstractions;
using FilePicker = Microsoft.Maui.Storage.FilePicker;

namespace PasswordManager.App.Platform
{
    /// <summary>
    /// MAUI implementation of <see cref="IFilePickerService"/> over FilePicker,
    /// CommunityToolkit FolderPicker and FileSaver.
    /// </summary>
    public class MauiFilePickerService : IFilePickerService
    {
        public async Task<string?> PickFileAsync(string? filterTitle = null, string[]? extensions = null)
        {
            try
            {
                var options = BuildOptions(filterTitle, extensions);
                var result = await FilePicker.Default.PickAsync(options);
                return result?.FullPath;
            }
            catch
            {
                return null;
            }
        }

        public async Task<PickedFile?> PickFileForReadAsync(string? filterTitle = null, string[]? extensions = null)
        {
            try
            {
                var options = BuildOptions(filterTitle, extensions);
                var result = await FilePicker.Default.PickAsync(options);
                if (result is null) return null;

                var stream = await result.OpenReadAsync();
                return new PickedFile(result.FileName, stream);
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

        public async Task<string?> SaveFileAsync(string suggestedFileName = "file.txt", byte[]? initialBytes = null)
        {
            try
            {
                using var stream = new MemoryStream(initialBytes ?? Array.Empty<byte>());
                var result = await FileSaver.Default.SaveAsync(suggestedFileName, stream, CancellationToken.None);
                return result.IsSuccessful ? result.FilePath : null;
            }
            catch
            {
                return null;
            }
        }

        public async Task<string?> SaveStreamAsync(string suggestedFileName, Stream content)
        {
            try
            {
                if (content.CanSeek) content.Position = 0;
                var result = await FileSaver.Default.SaveAsync(suggestedFileName, content, CancellationToken.None);
                return result.IsSuccessful ? result.FilePath : null;
            }
            catch
            {
                return null;
            }
        }

        private static PickOptions BuildOptions(string? filterTitle, string[]? extensions)
        {
            var options = new PickOptions { PickerTitle = filterTitle ?? "Select a file" };

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

            return options;
        }
    }
}
