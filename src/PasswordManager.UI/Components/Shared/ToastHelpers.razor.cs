using PasswordManager.UI.Services;

namespace PasswordManager.UI.Components.Shared
{
    public partial class ToastHost
    {
        private static string KindClass(ToastKind kind) => kind switch
        {
            ToastKind.Success => "success",
            ToastKind.Error => "error",
            ToastKind.Info => "info",
            ToastKind.Warning => "warning",
            _ => "info",
        };

        // Names into the Icons dictionary consumed by <Icon>.
        private static string KindIcon(ToastKind kind) => kind switch
        {
            ToastKind.Success => "check",
            ToastKind.Error => "x",
            ToastKind.Warning => "alert",
            _ => "info",
        };
    }
}
