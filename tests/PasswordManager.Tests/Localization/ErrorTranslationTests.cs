using System.Reflection;
using System.Text.Json;
using PasswordManager.Core.Exceptions;
using PasswordManager.UI.Localization;
using Xunit;

namespace PasswordManager.Tests.Localization
{
    /// <summary>
    /// Every user-facing failure must have a sentence in every language. Testers reported errors
    /// appearing in English on a Spanish device because the text came from an exception thrown in
    /// Infrastructure, where no translation exists; these tests keep that from creeping back as
    /// codes are added.
    /// </summary>
    public class ErrorTranslationTests
    {
        private static Dictionary<string, string> Catalogue(string language)
        {
            var assembly = typeof(Loc).Assembly;
            var name = assembly.GetManifestResourceNames()
                .Single(n => n.EndsWith($"Resources.{language}.json", StringComparison.OrdinalIgnoreCase));

            using var stream = assembly.GetManifestResourceStream(name)!;
            return JsonSerializer.Deserialize<Dictionary<string, string>>(stream)!;
        }

        /// <summary>
        /// Calls the same private resolver the UI uses, so the test exercises the real mapping
        /// rather than a copy of it that could drift.
        /// </summary>
        private static string KeyFor(AppErrorCode code)
        {
            var method = typeof(PasswordManager.UI.UserError).GetMethod("KeyFor",
                BindingFlags.NonPublic | BindingFlags.Static)!;
            return (string)method.Invoke(null, new object[] { code })!;
        }

        public static TheoryData<AppErrorCode> AllCodes()
        {
            var data = new TheoryData<AppErrorCode>();
            foreach (AppErrorCode code in Enum.GetValues<AppErrorCode>()) data.Add(code);
            return data;
        }

        [Theory]
        [MemberData(nameof(AllCodes))]
        public void EveryErrorCode_MapsToItsOwnKey(AppErrorCode code)
        {
            // A code that fell through to the generic arm would show "something went wrong"
            // instead of what actually happened.
            Assert.NotEqual("error.unexpected", KeyFor(code));
        }

        [Theory]
        [MemberData(nameof(AllCodes))]
        public void EveryErrorCode_IsTranslatedInBothLanguages(AppErrorCode code)
        {
            var key = KeyFor(code);

            foreach (var language in new[] { "en", "es" })
            {
                var catalogue = Catalogue(language);
                Assert.True(catalogue.ContainsKey(key), $"'{key}' is missing from {language}.json");
                Assert.False(string.IsNullOrWhiteSpace(catalogue[key]), $"'{key}' is empty in {language}.json");
            }
        }

        [Fact]
        public void BothCatalogues_HaveTheSameKeys()
        {
            var en = Catalogue("en").Keys.ToHashSet();
            var es = Catalogue("es").Keys.ToHashSet();

            Assert.Empty(en.Except(es));
            Assert.Empty(es.Except(en));
        }
    }
}
