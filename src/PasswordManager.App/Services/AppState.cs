using PasswordManager.Core.Models;
using PasswordManager.Core.Services;

namespace PasswordManager.App.Services
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

        public void Lock()
        {
            _service?.Dispose();
            _service = null;
            _account = null;
            NotifyStateChanged();
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
