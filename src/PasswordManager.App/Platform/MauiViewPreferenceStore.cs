using Microsoft.Maui.Storage;
using PasswordManager.UI.Services;

namespace PasswordManager.App.Platform
{
    /// <summary>MAUI implementation of <see cref="IViewPreferenceStore"/> backed by Preferences.</summary>
    public class MauiViewPreferenceStore : IViewPreferenceStore
    {
        private static string KeyFor(string scope) => $"view_mode_{scope}";

        public string? Get(string scope) => Preferences.Default.Get<string?>(KeyFor(scope), null);

        public void Set(string scope, string mode) => Preferences.Default.Set(KeyFor(scope), mode);
    }
}
