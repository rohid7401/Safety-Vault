using Microsoft.Maui.ApplicationModel.DataTransfer;
using PasswordManager.UI.Abstractions;

namespace PasswordManager.App.Platform
{
    /// <summary>MAUI implementation of <see cref="IClipboardService"/>.</summary>
    public class MauiClipboardService : IClipboardService
    {
        public Task SetTextAsync(string text) => Clipboard.Default.SetTextAsync(text);

        public Task<string?> GetTextAsync() => Clipboard.Default.GetTextAsync();
    }
}
