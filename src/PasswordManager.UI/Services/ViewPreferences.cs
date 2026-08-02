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
    /// </summary>
    public sealed class ViewPreferences
    {
        private readonly IViewPreferenceStore _store;
        private readonly Dictionary<ViewScope, ViewMode> _cache = new();

        public event Action? OnChanged;

        public ViewPreferences(IViewPreferenceStore store) => _store = store;

        private static ViewMode DefaultFor(ViewScope scope) =>
            scope == ViewScope.Dashboard ? ViewMode.Grid : ViewMode.List;

        public ViewMode Get(ViewScope scope)
        {
            if (_cache.TryGetValue(scope, out var cached)) return cached;

            // An unreadable or unrecognised stored value falls back to the default rather than
            // throwing — a bad preference must never keep a screen from rendering.
            var mode = Enum.TryParse<ViewMode>(_store.Get(scope.ToString()), out var stored)
                ? stored
                : DefaultFor(scope);

            _cache[scope] = mode;
            return mode;
        }

        public void Set(ViewScope scope, ViewMode mode)
        {
            if (Get(scope) == mode) return;

            _cache[scope] = mode;
            _store.Set(scope.ToString(), mode.ToString());
            OnChanged?.Invoke();
        }
    }
}
