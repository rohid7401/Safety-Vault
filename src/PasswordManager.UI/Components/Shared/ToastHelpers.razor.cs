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

        private static string KindIcon(ToastKind kind) => kind switch
        {
            ToastKind.Success => "✓",
            ToastKind.Error => "✕",
            ToastKind.Info => "ℹ",
            ToastKind.Warning => "⚠",
            _ => "•",
        };
    }
}
