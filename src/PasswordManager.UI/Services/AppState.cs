using PasswordManager.Core.Models;
using PasswordManager.Core.Services;

namespace PasswordManager.UI.Services
{
    /// <summary>
    /// Holds the application-level state: the active user account,
    /// the unlocked PasswordManagerService, and broadcasts state changes.
    /// </summary>
    public class AppState : IDisposable
    {
        private PasswordManagerService? _service;
        private UserAccount? _account;

        public PasswordManagerService? Service => _service;
        public UserAccount? Account => _account;
        public bool IsUnlocked => _service is not null && _account is not null;

        public event Action? OnStateChanged;

        public void Unlock(UserAccount account, PasswordManagerService service)
        {
            _account = account;
            _service = service;
            NotifyStateChanged();
        }

        public void Lock() => Lock(notify: true);

        /// <summary>
        /// Ends the session.
        ///
        /// <para>Pass <paramref name="notify"/> as false when the caller navigates away in the
        /// same breath. Announcing the change first re-renders whichever page is still on screen
        /// — now in a locked state it was never written for — and every page guards itself with
        /// <c>@if (AppState.Service is null) { Nav.NavigateTo("/"); return; }</c>, so the redirect
        /// fires from inside the render pass. Navigating first is not an option either: the page
        /// being opened still sees an unlocked vault and bounces to the dashboard. Staying quiet
        /// and letting the navigation drive the next render avoids both.</para>
        /// </summary>
        public void Lock(bool notify)
        {
            _service?.Dispose();
            _service = null;
            _account = null;
            if (notify) NotifyStateChanged();
        }

        private void NotifyStateChanged() => OnStateChanged?.Invoke();

        public void Dispose()
        {
            _service?.Dispose();
            _service = null;
            _account = null;
        }
    }
}
