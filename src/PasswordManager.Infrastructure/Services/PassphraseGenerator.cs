using System.Collections.Concurrent;
using System.Security.Cryptography;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    /// <summary>
    /// Passphrases from a wordlist, one per language.
    ///
    /// <para>The app's own first-run advice tells people four unrelated words beat eight
    /// characters with symbols, and until now offered no way to make any. This is that way.</para>
    ///
    /// <para>Words are lowercase ASCII by construction — no accents, no ñ — because a master
    /// phrase gets typed on keyboards the app has never seen, including the one on a friend's
    /// laptop at 2am. That costs nothing: the strength is in the count, not the alphabet.</para>
    /// </summary>
    public class PassphraseGenerator : IPassphraseGenerator
    {
        /// <summary>Parsed once per language and kept: the split is pure and the lists are small.</summary>
        private static readonly ConcurrentDictionary<string, string[]> Lists = new();

        /// <summary>English is the fallback for a UI language with no list of its own — a phrase
        /// in the wrong language beats no phrase at all.</summary>
        private static readonly Dictionary<string, string> Sources = new()
        {
            ["es"] = Resources.Wordlists.Es,
            ["en"] = Resources.Wordlists.En,
        };

        public string Generate(string language, PassphraseGeneratorOptions? options = null)
        {
            options ??= new PassphraseGeneratorOptions();
            var words = Load(language);

            var count = Math.Clamp(options.WordCount, 3, 12);
            var chosen = new string[count];
            for (var i = 0; i < count; i++)
            {
                var w = words[RandomNumberGenerator.GetInt32(words.Length)];
                chosen[i] = options.Capitalize ? char.ToUpperInvariant(w[0]) + w[1..] : w;
            }

            if (options.IncludeNumber)
            {
                var at = RandomNumberGenerator.GetInt32(count);
                chosen[at] += RandomNumberGenerator.GetInt32(10).ToString();
            }

            return string.Join(options.Separator ?? "-", chosen);
        }

        public string GenerateUsername(string language)
        {
            var words = Load(language);
            var a = words[RandomNumberGenerator.GetInt32(words.Length)];
            var b = words[RandomNumberGenerator.GetInt32(words.Length)];
            // Two digits, so it stays short enough to read out loud over a phone.
            return $"{a}-{b}-{RandomNumberGenerator.GetInt32(10, 100)}";
        }

        public double EntropyBits(string language, PassphraseGeneratorOptions options)
        {
            var size = WordCount(language);
            if (size <= 1) return 0;

            var count = Math.Clamp(options.WordCount, 3, 12);
            var bits = count * Math.Log2(size);

            // Only the digit itself is counted, not which word it landed on. Where the position
            // also has to be guessed the real figure is higher — a strength claim should err
            // downwards, never up.
            if (options.IncludeNumber) bits += Math.Log2(10);

            return bits;
        }

        public int WordCount(string language) => Load(language).Length;

        public int WordsForStrength(string language, double targetBits)
        {
            var perWord = Math.Log2(Math.Max(2, WordCount(language)));
            return Math.Clamp((int)Math.Ceiling(targetBits / perWord), 3, 12);
        }

        /// <summary>
        /// The list for a language, falling back to English. Deduplicated on the way in, so the
        /// count is the true number of possibilities: a word accidentally written twice would
        /// otherwise inflate the strength shown on screen while weakening the phrase behind it.
        /// </summary>
        private static string[] Load(string language)
        {
            var code = string.IsNullOrWhiteSpace(language) ? "en" : language.Trim().ToLowerInvariant();
            if (code.Length > 2) code = code[..2];
            if (!Sources.ContainsKey(code)) code = "en";

            return Lists.GetOrAdd(code, key => Sources[key]
                .Split('\n')
                .Select(w => w.Trim())
                .Where(w => w.Length > 0)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(w => w, StringComparer.Ordinal)
                .ToArray());
        }
    }
}
