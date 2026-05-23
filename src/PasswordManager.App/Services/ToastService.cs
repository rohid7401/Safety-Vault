namespace PasswordManager.App.Services
{
    /// <summary>
    /// App-wide toast/notification service. Components subscribe to OnShow,
    /// the global Toast component listens and renders inside MainLayout.
    /// </summary>
    public class ToastService
    {
        public event Action<ToastMessage>? OnShow;

        public void Show(string message, ToastKind kind = ToastKind.Success, int durationMs = 3500)
        {
            OnShow?.Invoke(new ToastMessage(message, kind, durationMs));
        }

        public void Success(string message) => Show(message, ToastKind.Success);
        public void Error(string message) => Show(message, ToastKind.Error, 5000);
        public void Info(string message) => Show(message, ToastKind.Info);
        public void Warning(string message) => Show(message, ToastKind.Warning);
    }

    public enum ToastKind { Success, Error, Info, Warning }

    public record ToastMessage(string Text, ToastKind Kind, int DurationMs);
}
