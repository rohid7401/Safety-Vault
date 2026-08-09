namespace PasswordManager.UI.Services
{
    public enum ViewMode { List, Grid }

    /// <summary>Screens that carry their own independent list/grid choice.</summary>
    public enum ViewScope { Dashboard, Passwords, Notes, Cards }

    /// <summary>
    /// Remembers whether each screen is shown as a list or a grid.
    ///
    /// <para>The scopes are deliberately independent: someone who wants the dashboard as tiles
    /// usually still wants their passwords as a list, so switching one must never move another.</para>
    ///
    /// <para>Defaults differ for the same reason. The dashboard is a fixed set of destinations
    /// where tiles read faster, so it starts as a grid; the vault screens start as lists, which
    /// carry more per row and is what existing users already know.</para>
    ///
    /// <para>Now stored per account through <see cref="AppSettings"/> rather than per device, so
    /// the choice follows the vault to a second device. The old device store is still read once,
    /// to carry over what someone had already set — see <see cref="MigrateFromDeviceStoreAsync"/>.</para>
    /// </summary>
    public sealed class ViewPreferences
    {
        private readonly AppSettings _settings;
        private readonly IViewPreferenceStore _legacyStore;

        public event Action? OnChanged;

        public ViewPreferences(AppSettings settings, IViewPreferenceStore legacyStore)
        {
            _settings = settings;
            _legacyStore = legacyStore;
            _settings.OnChanged += () => OnChanged?.Invoke();
        }

        private static ViewMode DefaultFor(ViewScope scope) =>
            scope == ViewScope.Dashboard ? ViewMode.Grid : ViewMode.List;

        private static Setting<ViewMode> SettingFor(ViewScope scope) =>
            Setting<ViewMode>.ForEnum($"view.{scope}", DefaultFor(scope));

        public ViewMode Get(ViewScope scope) => _settings.Get(SettingFor(scope));

        public Task SetAsync(ViewScope scope, ViewMode mode) =>
            _settings.SetAsync(SettingFor(scope), mode);

        /// <summary>
        /// Moves a choice made before these lived in the vault. Runs once per unlock and only
        /// fills scopes the account has never set, so it can never overwrite a newer choice made
        /// on this device — and an upgrade does not silently reset everyone's screens.
        /// </summary>
        public async Task MigrateFromDeviceStoreAsync()
        {
            foreach (var scope in Enum.GetValues<ViewScope>())
            {
                var stored = _legacyStore.Get(scope.ToString());
                if (Enum.TryParse<ViewMode>(stored, out var mode))
                    await _settings.SeedAsync(SettingFor(scope), mode);
            }
        }
    }
}
