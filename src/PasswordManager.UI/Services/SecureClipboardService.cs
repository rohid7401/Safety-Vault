using PasswordManager.UI.Abstractions;

namespace PasswordManager.UI.Services
{
    /// <summary>
    /// B2 — wraps <see cref="IClipboardService"/> so copying a secret (password, TOTP code)
    /// automatically clears the clipboard after a timeout, shrinking the window during which
    /// the secret sits there for any other app to read.
    ///
    /// Before clearing, it checks the clipboard still holds exactly what we put there — if the
    /// user copied something else in the meantime, we leave it alone. Copying again cancels
    /// any pending clear from a previous copy.
    ///
    /// This does not (and cannot) purge OS-level clipboard history (e.g. Windows Win+V) — see
    /// SECURITY.md N10 for that residual, platform-level limitation.
    /// </summary>
    public class SecureClipboardService
    {
        private static readonly TimeSpan DefaultClearAfter = TimeSpan.FromSeconds(30);

        private readonly IClipboardService _clipboard;
        private readonly TimeSpan _clearAfter;
        private CancellationTokenSource? _pendingClear;

        public SecureClipboardService(IClipboardService clipboard, TimeSpan? clearAfter = null)
        {
            _clipboard = clipboard;
            _clearAfter = clearAfter ?? DefaultClearAfter;
        }

        /// <summary>Copies a secret to the clipboard and schedules it to auto-clear.</summary>
        public async Task CopySensitiveAsync(string text)
        {
            _pendingClear?.Cancel();
            var cts = new CancellationTokenSource();
            _pendingClear = cts;

            await _clipboard.SetTextAsync(text);

            _ = ClearAfterDelayAsync(text, cts.Token);
        }

        private async Task ClearAfterDelayAsync(string copiedText, CancellationToken token)
        {
            try
            {
                await Task.Delay(_clearAfter, token);
            }
            catch (TaskCanceledException)
            {
                return;
            }

            if (token.IsCancellationRequested) return;

            var current = await _clipboard.GetTextAsync();
            if (current == copiedText)
                await _clipboard.SetTextAsync(string.Empty);
        }
    }
}
