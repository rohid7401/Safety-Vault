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

        /// <summary>
        /// The clear runs on a fire-and-forget task with two more async hops after its own delay
        /// (GetTextAsync, then SetTextAsync) before it is actually done. Waiting a fixed
        /// <c>Task.Delay</c> buffer for that to finish means guessing a margin, and on a loaded CI
        /// runner the guess was occasionally wrong — the assertion below caught the invocation
        /// mid-flight often enough to fail intermittently. Waiting on a signal set by the mock
        /// itself removes the guess: the test proceeds exactly when the real work is done, not
        /// after an arbitrary interval that may or may not have been enough.
        /// </summary>
        private static async Task WaitForCallAsync(Task signal, string because)
        {
            var completed = await Task.WhenAny(signal, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.True(completed == signal, $"Timed out waiting for {because}.");
        }

        [Fact]
        public async Task CopySensitiveAsync_ClearsClipboardAfterDelay_WhenContentUnchanged()
        {
            var clipboard = new Mock<IClipboardService>();
            clipboard.Setup(c => c.GetTextAsync()).ReturnsAsync("secret123");
            var cleared = new TaskCompletionSource<bool>();
            clipboard.Setup(c => c.SetTextAsync(string.Empty))
                .Callback(() => cleared.TrySetResult(true))
                .Returns(Task.CompletedTask);
            var svc = new SecureClipboardService(clipboard.Object, ShortDelay);

            await svc.CopySensitiveAsync("secret123");
            await WaitForCallAsync(cleared.Task, "the auto-clear to fire");

            clipboard.Verify(c => c.SetTextAsync(string.Empty), Times.Once);
        }

        [Fact]
        public async Task CopySensitiveAsync_DoesNotClear_WhenUserCopiedSomethingElseMeanwhile()
        {
            var clipboard = new Mock<IClipboardService>();
            var checkedClipboard = new TaskCompletionSource<bool>();
            // The user copied something else before the auto-clear fires.
            clipboard.Setup(c => c.GetTextAsync())
                .Callback(() => checkedClipboard.TrySetResult(true))
                .ReturnsAsync("something-else-the-user-copied");
            var svc = new SecureClipboardService(clipboard.Object, ShortDelay);

            await svc.CopySensitiveAsync("secret123");
            // GetTextAsync always runs once the delay elapses, whichever way the comparison
            // below it goes — so waiting for it pins down the moment the decision was made,
            // whether or not a clear follows.
            await WaitForCallAsync(checkedClipboard.Task, "the clipboard to be checked");

            clipboard.Verify(c => c.SetTextAsync(string.Empty), Times.Never);
        }

        [Fact]
        public async Task CopySensitiveAsync_SecondCopy_CancelsThePreviousPendingClear()
        {
            var clipboard = new Mock<IClipboardService>();
            clipboard.Setup(c => c.GetTextAsync()).ReturnsAsync("second-secret");
            var cleared = new TaskCompletionSource<bool>();
            clipboard.Setup(c => c.SetTextAsync(string.Empty))
                .Callback(() => cleared.TrySetResult(true))
                .Returns(Task.CompletedTask);
            var svc = new SecureClipboardService(clipboard.Object, ShortDelay);

            await svc.CopySensitiveAsync("first-secret");
            await Task.Delay(TimeSpan.FromMilliseconds(10)); // well before the first clear fires
            await svc.CopySensitiveAsync("second-secret");

            await WaitForCallAsync(cleared.Task, "the second copy's auto-clear to fire");

            // Only one clear should ever fire (from the second copy's timer), not two.
            clipboard.Verify(c => c.SetTextAsync(string.Empty), Times.Once);
        }
    }
}
