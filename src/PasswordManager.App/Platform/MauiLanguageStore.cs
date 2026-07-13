using Microsoft.Maui.Storage;
using PasswordManager.UI.Localization;

namespace PasswordManager.App.Platform
{
    /// <summary>MAUI implementation of <see cref="ILanguageStore"/> backed by Preferences.</summary>
    public class MauiLanguageStore : ILanguageStore
    {
        private const string Key = "app_language";

        public string? GetSavedLanguage()
        {
            var value = Preferences.Default.Get(Key, string.Empty);
            return string.IsNullOrEmpty(value) ? null : value;
        }

        public void SaveLanguage(string code) => Preferences.Default.Set(Key, code);
    }
}
