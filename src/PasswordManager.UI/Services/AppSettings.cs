using PasswordManager.Core.Services;

namespace PasswordManager.UI.Services
{
    /// <summary>
    /// One place for everything the user can configure about their account.
    ///
    /// <para>Replaces a growing set of parallel stores — each preference used to arrive with its
    /// own interface, its own platform implementation and its own idea of what "not set" means.
    /// Settings live inside the vault, so they belong to the account rather than the handset: two
    /// accounts on one phone keep their own, and they travel in the backup. Language is the
    /// deliberate exception and stays device-local, because the sign-in screen has to be readable
    /// before any vault is open.</para>
    ///
    /// <para>Values are cached in memory once the vault is unlocked. Reading a preference happens
    /// during render, and going to the repository for each one would decrypt the vault on every
    /// frame; writes go through to disk immediately, since losing a setting the user just chose is
    /// worse than the cost of one save.</para>
    /// </summary>
    public sealed class AppSettings
    {
        private readonly AppState _appState;
        private Dictionary<string, string> _values = new(StringComparer.Ordinal);
        private bool _loaded;

        /// <summary>Raised after any change, so open screens re-render with the new value.</summary>
        public event Action? OnChanged;

        public AppSettings(AppState appState)
        {
            _appState = appState;
            // A locked vault leaves nothing to read; the next unlock loads the new account's own.
            _appState.OnStateChanged += Invalidate;
        }

        private void Invalidate()
        {
            _loaded = false;
            _values = new Dictionary<string, string>(StringComparer.Ordinal);
        }

        /// <summary>
        /// Loads this account's settings. Safe to call repeatedly; only the first call after an
        /// unlock touches the vault.
        /// </summary>
        public async Task EnsureLoadedAsync()
        {
            if (_loaded || _appState.Service is null) return;

            _values = await _appState.Service.GetSettingsAsync();
            _loaded = true;
        }

        /// <summary>
        /// The stored value for <paramref name="setting"/>, or its default when the user has never
        /// chosen. Never throws on a stored value that no longer parses — a preference written by
        /// a different build must not be able to stop a screen from rendering.
        /// </summary>
        public T Get<T>(Setting<T> setting) =>
            _values.TryGetValue(setting.Key, out var raw) && setting.TryParse(raw, out var parsed)
                ? parsed
                : setting.Default;

        /// <summary>Stores a value, or clears it back to the default when it equals the default.</summary>
        public async Task SetAsync<T>(Setting<T> setting, T value)
        {
            if (_appState.Service is null) return;
            if (EqualityComparer<T>.Default.Equals(Get(setting), value)) return;

            // Storing a value identical to the default would freeze it: a later change to what the
            // app considers sensible would not reach anyone who had merely accepted the old one.
            var isDefault = EqualityComparer<T>.Default.Equals(value, setting.Default);
            var serialized = isDefault ? null : setting.Serialize(value);

            if (serialized is null) _values.Remove(setting.Key);
            else _values[setting.Key] = serialized;

            await _appState.Service.SetSettingsAsync(
                new Dictionary<string, string?> { [setting.Key] = serialized });

            OnChanged?.Invoke();
        }

        /// <summary>
        /// Adopts a value only if the user has never chosen one. Used to carry a preference over
        /// from the per-device store it used to live in, so an upgrade does not silently reset
        /// what someone already set.
        /// </summary>
        public async Task SeedAsync<T>(Setting<T> setting, T value)
        {
            if (_values.ContainsKey(setting.Key)) return;
            await SetAsync(setting, value);
        }

        /// <summary>Everything stored, for the backup. Copied so callers cannot mutate the cache.</summary>
        public IReadOnlyDictionary<string, string> All() =>
            new Dictionary<string, string>(_values, StringComparer.Ordinal);
    }

    /// <summary>
    /// One configurable preference: its key, its default, and how it converts to and from the
    /// stored string.
    ///
    /// <para>Carries <see cref="RequiresPaidTier"/> from the start. Adding that later would mean
    /// revisiting every place a setting is read; leaving the flag here now costs nothing and means
    /// a future tier check happens in one place.</para>
    /// </summary>
    public sealed class Setting<T>
    {
        public string Key { get; }
        public T Default { get; }
        public bool RequiresPaidTier { get; }

        private readonly Func<T, string> _serialize;
        private readonly TryParser _tryParse;

        private delegate bool TryParser(string raw, out T value);

        private Setting(string key, T fallback, Func<T, string> serialize, TryParser tryParse, bool paid)
        {
            Key = key;
            Default = fallback;
            _serialize = serialize;
            _tryParse = tryParse;
            RequiresPaidTier = paid;
        }

        public string Serialize(T value) => _serialize(value);
        public bool TryParse(string raw, out T value) => _tryParse(raw, out value);

        public static Setting<TEnum> ForEnum<TEnum>(string key, TEnum fallback, bool paid = false)
            where TEnum : struct, Enum
        {
            return new Setting<TEnum>(
                key, fallback,
                v => v.ToString()!,
                (string raw, out TEnum value) => Enum.TryParse(raw, out value),
                paid);
        }

        public static Setting<int> ForInt(string key, int fallback, bool paid = false) =>
            new(key, fallback,
                v => v.ToString(),
                (string raw, out int value) => int.TryParse(raw, out value),
                paid);

        public static Setting<bool> ForBool(string key, bool fallback, bool paid = false) =>
            new(key, fallback,
                v => v ? "true" : "false",
                (string raw, out bool value) => bool.TryParse(raw, out value),
                paid);
    }
}
