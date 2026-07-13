using System.Globalization;
using System.Text.Json;

namespace PasswordManager.UI.Localization
{
    /// <summary>One selectable UI language.</summary>
    public readonly record struct LanguageOption(string Code, string Name);

    /// <summary>
    /// App-wide string translator. Translations live in embedded JSON files under
    /// <c>Localization/Resources/&lt;code&gt;.json</c> (one flat key→text map per language).
    ///
    /// To add a new language:
    ///   1. Copy <c>Resources/en.json</c> to e.g. <c>Resources/fr.json</c> and translate the values.
    ///   2. Add a <see cref="LanguageOption"/> for it in <see cref="BuildAvailable"/>.
    /// That's it — the file is picked up automatically at startup.
    ///
    /// Usage in a component: <c>@inject Loc L</c> then <c>@L["nav.passwords"]</c>, and subscribe
    /// to <see cref="OnChanged"/> (like AppState.OnStateChanged) so it re-renders on language switch.
    /// </summary>
    public sealed class Loc
    {
        private const string FallbackLanguage = "en";

        private readonly Dictionary<string, Dictionary<string, string>> _langs =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly ILanguageStore _store;

        public event Action? OnChanged;

        public string CurrentLanguage { get; private set; } = FallbackLanguage;

        public IReadOnlyList<LanguageOption> Available { get; }

        public Loc(ILanguageStore store)
        {
            _store = store;
            LoadResources();
            Available = BuildAvailable();

            var saved = Normalize(_store.GetSavedLanguage());
            var device = Normalize(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName);
            CurrentLanguage = saved ?? device ?? "es";
            ApplyCulture(CurrentLanguage);
        }

        /// <summary>The languages offered in the picker. Add new entries here.</summary>
        private List<LanguageOption> BuildAvailable() => new()
        {
            new LanguageOption("es", "Español"),
            new LanguageOption("en", "English"),
        };

        /// <summary>Translate a key for the current language, falling back to English then the key itself.</summary>
        public string this[string key]
        {
            get
            {
                if (_langs.TryGetValue(CurrentLanguage, out var d) && d.TryGetValue(key, out var v))
                    return v;
                if (_langs.TryGetValue(FallbackLanguage, out var f) && f.TryGetValue(key, out var fv))
                    return fv;
                return key;
            }
        }

        /// <summary>Translate then <see cref="string.Format(string, object?[])"/> with the given args.</summary>
        public string Format(string key, params object?[] args) => string.Format(this[key], args);

        public void SetLanguage(string code)
        {
            if (string.IsNullOrEmpty(code) || code == CurrentLanguage || !_langs.ContainsKey(code))
                return;

            CurrentLanguage = code;
            _store.SaveLanguage(code);
            ApplyCulture(code);
            OnChanged?.Invoke();
        }

        private string? Normalize(string? code)
            => !string.IsNullOrEmpty(code) && _langs.ContainsKey(code) ? code.ToLowerInvariant() : null;

        private static void ApplyCulture(string code)
        {
            try
            {
                var culture = new CultureInfo(code);
                CultureInfo.CurrentCulture = culture;
                CultureInfo.CurrentUICulture = culture;
                CultureInfo.DefaultThreadCurrentCulture = culture;
                CultureInfo.DefaultThreadCurrentUICulture = culture;
            }
            catch (CultureNotFoundException) { /* keep previous culture */ }
        }

        private void LoadResources()
        {
            var asm = typeof(Loc).Assembly;
            foreach (var name in asm.GetManifestResourceNames())
            {
                // e.g. "PasswordManager.UI.Localization.Resources.es.json"
                if (!name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) continue;
                if (!name.Contains(".Resources.", StringComparison.OrdinalIgnoreCase)) continue;

                var parts = name.Split('.');
                if (parts.Length < 2) continue;
                var code = parts[^2].ToLowerInvariant(); // segment before ".json"

                using var stream = asm.GetManifestResourceStream(name);
                if (stream is null) continue;

                try
                {
                    var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(stream);
                    if (dict is not null)
                        _langs[code] = new Dictionary<string, string>(dict, StringComparer.Ordinal);
                }
                catch (JsonException) { /* skip malformed resource */ }
            }
        }
    }
}
