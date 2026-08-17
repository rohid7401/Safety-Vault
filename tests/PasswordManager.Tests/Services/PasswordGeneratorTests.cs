using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class PasswordGeneratorTests
    {
        private readonly PasswordGenerator _generator = new();

        [Fact]
        public void Generate_DefaultOptions_ReturnsPasswordWithLength20()
        {
            var password = _generator.Generate();
            Assert.Equal(20, password.Length);
        }

        [Theory]
        [InlineData(8)]
        [InlineData(16)]
        [InlineData(32)]
        [InlineData(64)]
        public void Generate_CustomLength_ReturnsCorrectLength(int length)
        {
            var options = new PasswordGeneratorOptions { Length = length };
            var password = _generator.Generate(options);
            Assert.Equal(length, password.Length);
        }

        [Fact]
        public void Generate_AllCharSets_ContainsAllTypes()
        {
            var options = new PasswordGeneratorOptions { Length = 40 };
            var password = _generator.Generate(options);

            Assert.Contains(password, char.IsUpper);
            Assert.Contains(password, char.IsLower);
            Assert.Contains(password, char.IsDigit);
            Assert.Contains(password, c => "!@#$%^&*()-_=+[]{}|;:,.<>?".Contains(c));
        }

        [Fact]
        public void Generate_UppercaseOnly_ContainsOnlyUppercase()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 20,
                IncludeLowercase = false,
                IncludeDigits = false,
                IncludeSpecial = false
            };
            var password = _generator.Generate(options);
            Assert.All(password, c => Assert.True(char.IsUpper(c)));
        }

        [Fact]
        public void Generate_ExcludeChars_DoesNotContainExcluded()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 50,
                ExcludeChars = "aeiouAEIOU0159"
            };
            var password = _generator.Generate(options);
            Assert.All(password, c => Assert.DoesNotContain(c.ToString(), "aeiouAEIOU0159"));
        }

        [Fact]
        public void Generate_LengthTooShort_Throws()
        {
            var options = new PasswordGeneratorOptions { Length = 2 };
            var ex = Assert.Throws<LocalizedArgumentException>(() => _generator.Generate(options));
            Assert.Equal(AppErrorCode.PasswordLengthTooShort, ex.Code);
        }

        [Fact]
        public void Generate_NoCharSets_Throws()
        {
            var options = new PasswordGeneratorOptions
            {
                IncludeUppercase = false,
                IncludeLowercase = false,
                IncludeDigits = false,
                IncludeSpecial = false
            };
            var ex = Assert.Throws<LocalizedArgumentException>(() => _generator.Generate(options));
            Assert.Equal(AppErrorCode.NoCharacterSetEnabled, ex.Code);
        }

        [Fact]
        public void Generate_TwoCallsProduceDifferentPasswords()
        {
            var p1 = _generator.Generate();
            var p2 = _generator.Generate();
            Assert.NotEqual(p1, p2);
        }

        [Theory]
        [InlineData("", 0)]
        [InlineData("abc", 1)]
        [InlineData("Abc1", 3)]
        [InlineData("Abc1!xyz", 5)]
        [InlineData("Abc1!xyzLongPassword!!", 8)]
        public void CalculateStrength_ReturnsExpectedScore(string password, int expectedMinScore)
        {
            var score = _generator.CalculateStrength(password);
            Assert.InRange(score, expectedMinScore, 8);
        }

        // ── Include-word feature ──

        [Fact]
        public void Generate_IncludeWord_ContainsWordAndCorrectLength()
        {
            var options = new PasswordGeneratorOptions { Length = 20, IncludeWord = "yuki" };
            var password = _generator.Generate(options);

            Assert.Contains("yuki", password);
            Assert.Equal(20, password.Length);
        }

        [Fact]
        public void Generate_WordFillsWholeLength_ReturnsExactlyTheWord()
        {
            var options = new PasswordGeneratorOptions { Length = 4, IncludeWord = "yuki" };
            var password = _generator.Generate(options);
            Assert.Equal("yuki", password);
        }

        [Fact]
        public void Validate_WordLongerThanLength_ReportsConflict()
        {
            var options = new PasswordGeneratorOptions { Length = 3, IncludeWord = "yuki" };
            Assert.Contains(GeneratorConflict.WordLongerThanLength, _generator.Validate(options));
        }

        [Fact]
        public void Validate_WordContainsExcludedChar_ReportsConflict()
        {
            var options = new PasswordGeneratorOptions { Length = 20, IncludeWord = "yuki", ExcludeChars = "k" };
            Assert.Contains(GeneratorConflict.WordContainsExcludedChars, _generator.Validate(options));
        }

        [Fact]
        public void Validate_NoConflicts_ReturnsEmpty()
        {
            var options = new PasswordGeneratorOptions { Length = 20, IncludeWord = "yuki" };
            Assert.Empty(_generator.Validate(options));
        }

        [Fact]
        public void Generate_ConflictingOptions_ThrowsGeneratorConstraintException()
        {
            // Valid length, but excludes a character the word needs → unsatisfiable.
            var options = new PasswordGeneratorOptions { Length = 20, IncludeWord = "yuki", ExcludeChars = "k" };
            Assert.Throws<GeneratorConstraintException>(() => _generator.Generate(options));
        }

        [Fact]
        public void ResolveConflicts_MakesOptionsSatisfiable_ThenGenerates()
        {
            // 3-char length, excludes 'k', but wants "yuki" — three-way conflict.
            var options = new PasswordGeneratorOptions
            {
                Length = 3,
                IncludeWord = "yuki",
                ExcludeChars = "k",
            };

            Assert.NotEmpty(_generator.Validate(options));

            _generator.ResolveConflicts(options);

            Assert.Empty(_generator.Validate(options));
            Assert.True(options.Length >= "yuki".Length);
            Assert.DoesNotContain('k', options.ExcludeChars);

            var password = _generator.Generate(options);
            Assert.Contains("yuki", password);
        }

        // ── Count quotas ─────────────────────────────────────────────
        // These loop rather than draw once: a constraint that holds by luck on one draw and
        // fails on the next is exactly the bug that construction replaced rejection sampling to
        // avoid, and a single-draw test would not have caught it.

        private const string SpecialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?";

        [Fact]
        public void Generate_DigitQuota_HoldsOnEveryDraw()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 16,
                LimitDigits = true,
                MinDigits = 3,
                MaxDigits = 5,
            };

            for (var i = 0; i < 200; i++)
            {
                var password = _generator.Generate(options);
                Assert.InRange(password.Count(char.IsDigit), 3, 5);
                Assert.Equal(16, password.Length);
            }
        }

        [Fact]
        public void Generate_ExactSpecialCount_HoldsOnEveryDraw()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 20,
                LimitSpecial = true,
                MinSpecial = 2,
                MaxSpecial = 2,
            };

            for (var i = 0; i < 200; i++)
                Assert.Equal(2, _generator.Generate(options).Count(c => SpecialChars.Contains(c)));
        }

        [Fact]
        public void Generate_ZeroMaximum_ProducesNoneOfThatClass()
        {
            // "No symbols at all" has to be sayable through the quota and not only by switching
            // the class off — someone who caps it at zero means zero.
            var options = new PasswordGeneratorOptions
            {
                Length = 14,
                LimitSpecial = true,
                MinSpecial = 0,
                MaxSpecial = 0,
            };

            for (var i = 0; i < 100; i++)
                Assert.DoesNotContain(_generator.Generate(options), c => SpecialChars.Contains(c));
        }

        [Fact]
        public void Generate_QuotasFillingTheWholeLength_StillSucceeds()
        {
            // Digits and symbols account for every character, leaving no room for letters.
            var options = new PasswordGeneratorOptions
            {
                Length = 10,
                IncludeUppercase = false,
                IncludeLowercase = false,
                LimitDigits = true,
                MinDigits = 6,
                MaxDigits = 6,
                LimitSpecial = true,
                MinSpecial = 4,
                MaxSpecial = 4,
            };

            var password = _generator.Generate(options);
            Assert.Equal(6, password.Count(char.IsDigit));
            Assert.Equal(4, password.Count(c => SpecialChars.Contains(c)));
        }

        [Fact]
        public void Generate_RequiredCharacters_AreNotLeftAtTheFront()
        {
            // The minimums are placed first and then shuffled. Without the shuffle every
            // password would open with its digits — a pattern worth more to an attacker than
            // the quota costs them.
            var options = new PasswordGeneratorOptions
            {
                Length = 20,
                IncludeSpecial = false,
                LimitDigits = true,
                MinDigits = 4,
                MaxDigits = 4,
            };

            var startsWithDigit = 0;
            for (var i = 0; i < 200; i++)
                if (char.IsDigit(_generator.Generate(options)[0])) startsWithDigit++;

            // 4 of 20 positions carry a digit, so roughly a fifth of draws should start with
            // one. Near 200 would mean the shuffle never ran.
            Assert.InRange(startsWithDigit, 5, 100);
        }

        [Fact]
        public void Generate_ExcludeAmbiguous_DropsLookAlikesAndLeavesTheUserListAlone()
        {
            var options = new PasswordGeneratorOptions { Length = 40, ExcludeAmbiguous = true };

            for (var i = 0; i < 50; i++)
                Assert.DoesNotContain(_generator.Generate(options), c => "0O1lI|".Contains(c));

            // Applied on top of ExcludeChars, never merged into it, so switching it off returns
            // exactly the characters it removed.
            Assert.Equal(string.Empty, options.ExcludeChars);
        }

        [Fact]
        public void Generate_ExcludeProblematic_DropsShellAndMarkupPunctuation()
        {
            var options = new PasswordGeneratorOptions { Length = 40, ExcludeProblematic = true };

            for (var i = 0; i < 50; i++)
                Assert.DoesNotContain(_generator.Generate(options), c => "&$;<>|".Contains(c));

            Assert.Equal(string.Empty, options.ExcludeChars);
        }

        [Fact]
        public void Generate_ExcludeProblematic_IsIndependentOfExcludeAmbiguous()
        {
            // The two switches answer different questions, so neither may imply the other. The
            // pipe is the one character both sets claim, and is therefore not evidence either way.
            var problematicOnly = new PasswordGeneratorOptions { Length = 60, ExcludeProblematic = true };
            var ambiguousOnly = new PasswordGeneratorOptions { Length = 60, ExcludeAmbiguous = true };

            var withProblematicOff = string.Concat(Enumerable.Range(0, 40).Select(_ => _generator.Generate(ambiguousOnly)));
            var withAmbiguousOff = string.Concat(Enumerable.Range(0, 40).Select(_ => _generator.Generate(problematicOnly)));

            // Excluding look-alikes must still leave the awkward punctuation in play...
            Assert.Contains(withProblematicOff, c => "&$;<>".Contains(c));
            // ...and excluding the punctuation must leave the look-alikes in play.
            Assert.Contains(withAmbiguousOff, c => "0O1lI".Contains(c));
        }

        [Fact]
        public void ResolveConflicts_ExcludeProblematic_YieldsToAWordThatNeedsThoseCharacters()
        {
            // Same rule the ambiguous switch follows: a word the user asked for wins over an
            // exclusion, because a password that silently dropped characters out of their own
            // word would not be the thing they asked for.
            var options = new PasswordGeneratorOptions
            {
                Length = 20,
                IncludeWord = "a&b",
                ExcludeProblematic = true,
            };

            _generator.ResolveConflicts(options);

            Assert.False(options.ExcludeProblematic);
            Assert.Contains("a&b", _generator.Generate(options));
        }

        [Fact]
        public void ResolveConflicts_ExcludeProblematic_SurvivesAWordThatDoesNotNeedIt()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 20,
                IncludeWord = "yuki",
                ExcludeProblematic = true,
            };

            _generator.ResolveConflicts(options);

            Assert.True(options.ExcludeProblematic);
            Assert.DoesNotContain(_generator.Generate(options), c => "&$;<>|".Contains(c));
        }

        [Fact]
        public void Generate_IncludedWord_CountsTowardTheQuota()
        {
            // "r2d2" brings two digits of its own, so a cap of two leaves the filler none.
            var options = new PasswordGeneratorOptions
            {
                Length = 16,
                IncludeWord = "r2d2",
                LimitDigits = true,
                MinDigits = 0,
                MaxDigits = 2,
            };

            for (var i = 0; i < 100; i++)
            {
                var password = _generator.Generate(options);
                Assert.Contains("r2d2", password);
                Assert.Equal(2, password.Count(char.IsDigit));
            }
        }

        // ── Conflicts ────────────────────────────────────────────────

        [Fact]
        public void Validate_InvertedRange_IsReported()
        {
            var options = new PasswordGeneratorOptions { LimitDigits = true, MinDigits = 5, MaxDigits = 2 };
            Assert.Contains(GeneratorConflict.CountRangeInverted, _generator.Validate(options));
        }

        [Fact]
        public void Validate_MinimumsBeyondLength_IsReported()
        {
            var options = new PasswordGeneratorOptions
            {
                Length = 8,
                LimitDigits = true,
                MinDigits = 5,
                MaxDigits = 6,
                LimitSpecial = true,
                MinSpecial = 5,
                MaxSpecial = 6,
            };
            Assert.Contains(GeneratorConflict.MinimumsExceedLength, _generator.Validate(options));
        }

        [Fact]
        public void Validate_CapsTooLowToFillTheLength_IsReported()
        {
            // No letters to fall back on, and the two caps together fall short of 20.
            var options = new PasswordGeneratorOptions
            {
                Length = 20,
                IncludeUppercase = false,
                IncludeLowercase = false,
                LimitDigits = true,
                MinDigits = 0,
                MaxDigits = 4,
                LimitSpecial = true,
                MinSpecial = 0,
                MaxSpecial = 4,
            };
            Assert.Contains(GeneratorConflict.MaximumsBelowLength, _generator.Validate(options));
        }

        [Fact]
        public void Validate_QuotaOnDisabledSet_IsReported()
        {
            var options = new PasswordGeneratorOptions { IncludeSpecial = false, LimitSpecial = true };
            Assert.Contains(GeneratorConflict.LimitOnDisabledSet, _generator.Validate(options));
        }

        [Fact]
        public void ResolveConflicts_ClearsEveryConflictAtOnce()
        {
            // The awkward ones together: an inverted range, minimums past the length, a quota on
            // a class that is off, and nothing left to fill with.
            var options = new PasswordGeneratorOptions
            {
                Length = 6,
                IncludeUppercase = false,
                IncludeLowercase = false,
                IncludeSpecial = false,
                LimitDigits = true,
                MinDigits = 9,
                MaxDigits = 2,
                LimitSpecial = true,
                MinSpecial = 3,
                MaxSpecial = 1,
            };

            _generator.ResolveConflicts(options);

            Assert.Empty(_generator.Validate(options));
            // And what comes out is actually producible, which is the point of resolving.
            Assert.Equal(options.Length, _generator.Generate(options).Length);
        }
    }
}
