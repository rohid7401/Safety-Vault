namespace PasswordManager.UI.Abstractions
{
    /// <summary>
    /// Platform-neutral clipboard access. Implemented per shell:
    /// MAUI uses Microsoft.Maui Clipboard; a future web shell uses navigator.clipboard.
    /// </summary>
    public interface IClipboardService
    {
        Task SetTextAsync(string text);
    }
}
