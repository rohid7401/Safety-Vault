using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class PassphraseGeneratorTests
    {
        private readonly PassphraseGenerator _generator = new();

        [Theory]
        [InlineData("es")]
        [InlineData("en")]
        public void Wordlist_IsEmbeddedAndUsable(string language)
        {
            // Also proves the .txt files actually made it into the assembly: without the
            // EmbeddedResource entry this throws rather than quietly generating nothing.
            Assert.True(_generator.WordCount(language) > 200);
        }

        [Theory]
        [InlineData("es")]
        [InlineData("en")]
        public void Wordlist_IsPlainLowercaseAscii(string language)
        {
            // A master phrase gets typed on keyboards this app has never seen. An accent or an ñ
            // in the list would make some phrases unreachable on one of them, and the person
            // would have no way to know which word was the problem.
            var phrase = _generator.Generate(language,
                new PassphraseGeneratorOptions { WordCount = 12, Capitalize = false, Separator = " " });

            Assert.All(phrase.Split(' '),
                word => Assert.Matches("^[a-z]{3,12}$", word));
        }

        [Fact]
        public void Generate_ProducesTheRequestedNumberOfWords()
        {
            for (var count = 3; count <= 12; count++)
            {
                var options = new PassphraseGeneratorOptions { WordCount = count, Separator = "-" };
                Assert.Equal(count, _generator.Generate("es", options).Split('-').Length);
            }
        }

        [Fact]
        public void Generate_IsNotDeterministic()
        {
            var options = new PassphraseGeneratorOptions { WordCount = 6 };
            var seen = new HashSet<string>();
            for (var i = 0; i < 50; i++) seen.Add(_generator.Generate("es", options));

            // Six words from a list of hundreds: a repeat inside fifty draws would mean the
            // random source is not random.
            Assert.Equal(50, seen.Count);
        }

        [Fact]
        public void Generate_IncludeNumber_AddsExactlyOneDigit()
        {
            var options = new PassphraseGeneratorOptions { WordCount = 5, IncludeNumber = true };
            for (var i = 0; i < 50; i++)
                Assert.Equal(1, _generator.Generate("es", options).Count(char.IsDigit));
        }

        [Fact]
        public void EntropyBits_ComesFromTheRealListSize()
        {
            var options = new PassphraseGeneratorOptions { WordCount = 6 };
            var expected = 6 * Math.Log2(_generator.WordCount("es"));

            // Read from the data, never from a constant: if someone adds words to the file the
            // figure on screen has to move with them, and if someone removes words it has to
            // fall. A hard-coded number would keep claiming the old strength.
            Assert.Equal(expected, _generator.EntropyBits("es", options), 6);
        }

        [Fact]
        public void EntropyBits_CountsTheDigitConservatively()
        {
            var plain = new PassphraseGeneratorOptions { WordCount = 5 };
            var withNumber = new PassphraseGeneratorOptions { WordCount = 5, IncludeNumber = true };

            var gain = _generator.EntropyBits("es", withNumber) - _generator.EntropyBits("es", plain);

            // log2(10). The position of the digit is also random, so the true gain is higher —
            // a strength claim is the one number that should be understated.
            Assert.Equal(Math.Log2(10), gain, 6);
            Assert.True(gain < Math.Log2(_generator.WordCount("es")),
                "One digit must never be worth more than one more word, or the advice inverts.");
        }

        [Fact]
        public void WordsForStrength_ReturnsTheShortestPhraseThatReachesTheTarget()
        {
            var words = _generator.WordsForStrength("es", 60);
            var perWord = Math.Log2(_generator.WordCount("es"));

            Assert.True(words * perWord >= 60, "The default must actually reach the target.");
            Assert.True((words - 1) * perWord < 60, "And must not overshoot by a whole word.");
        }

        [Fact]
        public void UnknownLanguage_FallsBackInsteadOfThrowing()
        {
            // Someone reading the app in a language with no list still deserves a passphrase.
            var phrase = _generator.Generate("de", new PassphraseGeneratorOptions { WordCount = 4 });
            Assert.Equal(4, phrase.Split('-').Length);
        }

        [Fact]
        public void GenerateUsername_IsShortAndReadable()
        {
            for (var i = 0; i < 20; i++)
            {
                var name = _generator.GenerateUsername("es");
                var parts = name.Split('-');
                Assert.Equal(3, parts.Length);
                Assert.Matches("^[a-z]{3,12}$", parts[0]);
                Assert.Matches("^[a-z]{3,12}$", parts[1]);
                Assert.Matches("^[0-9]{2}$", parts[2]);
            }
        }
    }
}
