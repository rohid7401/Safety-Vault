using Moq;
using PasswordManager.UI.Abstractions;
using PasswordManager.UI.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>B2 — clipboard auto-clear after copying a secret.</summary>
    public class SecureClipboardServiceTests
    {
        private static readonly TimeSpan ShortDelay = TimeSpan.FromMilliseconds(50);

        [Fact]
        public async Task CopySensitiveAsync_SetsClipboardImmediately()
        {
            var clipboard = new Mock<IClipboardService>();
            var svc = new SecureClipboardService(clipboard.Object, ShortDelay);

            await svc.CopySensitiveAsync("secret123");

            clipboard.Verify(c => c.SetTextAsync("secret123"), Times.Once);
        }

        [Fact]
        public async Task CopySensitiveAsync_ClearsClipboardAfterDelay_WhenContentUnchanged()
        {
            var clipboard = new Mock<IClipboardService>();
            clipboard.Setup(c => c.GetTextAsync()).ReturnsAsync("secret123");
            var svc = new SecureClipboardService(clipboard.Object, ShortDelay);

            await svc.CopySensitiveAsync("secret123");
            await Task.Delay(ShortDelay + TimeSpan.FromMilliseconds(150));

            clipboard.Verify(c => c.SetTextAsync(string.Empty), Times.Once);
        }

        [Fact]
        public async Task CopySensitiveAsync_DoesNotClear_WhenUserCopiedSomethingElseMeanwhile()
        {
            var clipboard = new Mock<IClipboardService>();
            // The user copied something else before the auto-clear fires.
            clipboard.Setup(c => c.GetTextAsync()).ReturnsAsync("something-else-the-user-copied");
            var svc = new SecureClipboardService(clipboard.Object, ShortDelay);

            await svc.CopySensitiveAsync("secret123");
            await Task.Delay(ShortDelay + TimeSpan.FromMilliseconds(150));

            clipboard.Verify(c => c.SetTextAsync(string.Empty), Times.Never);
        }

        [Fact]
        public async Task CopySensitiveAsync_SecondCopy_CancelsThePreviousPendingClear()
        {
            var clipboard = new Mock<IClipboardService>();
            clipboard.Setup(c => c.GetTextAsync()).ReturnsAsync("second-secret");
            var svc = new SecureClipboardService(clipboard.Object, ShortDelay);

            await svc.CopySensitiveAsync("first-secret");
            await Task.Delay(TimeSpan.FromMilliseconds(10)); // well before the first clear fires
            await svc.CopySensitiveAsync("second-secret");

            await Task.Delay(ShortDelay + TimeSpan.FromMilliseconds(150));

            // Only one clear should ever fire (from the second copy's timer), not two.
            clipboard.Verify(c => c.SetTextAsync(string.Empty), Times.Once);
        }
    }
}
