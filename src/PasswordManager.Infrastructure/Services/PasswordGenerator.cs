using System.Security.Cryptography;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    public class PasswordGenerator : IPasswordGenerator
    {
        private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
        private const string Digits = "0123456789";
        private const string Special = "!@#$%^&*()-_=+[]{}|;:,.<>?";

        /// <summary>
        /// The glyphs that get read wrong: capital O against zero, and lowercase L against
        /// capital i, one and the pipe. Only these — widening it to punctuation people merely
        /// dislike would quietly cost entropy for no legibility gained.
        /// </summary>
        private const string Ambiguous = "0O1lI|";

        /// <summary>
        /// The punctuation other software mishandles: shell metacharacters and the ones that have
        /// to be escaped in HTML or a query string. A password containing these is not less safe —
        /// it is the thing that gets refused by a signup form or truncated on the way into a
        /// config file.
        ///
        /// <para>Quotes, the backslash and the backtick are the usual companions of this list and
        /// are absent from it because <see cref="Special"/> never generates them in the first
        /// place; adding them here would only suggest a protection that was never needed.</para>
        /// </summary>
        private const string Problematic = "&$;<>|";

        public string Generate(PasswordGeneratorOptions? options = null)
        {
            options ??= new PasswordGeneratorOptions();
            var word = options.IncludeWord ?? string.Empty;

            if (options.Length < 4)
                throw new LocalizedArgumentException(AppErrorCode.PasswordLengthTooShort, 4);

            // Every class off is its own error rather than a generic conflict: it is the one
            // mistake with a single obvious remedy, and callers match on this code to say so.
            if (!options.IncludeUppercase && !options.IncludeLowercase &&
                !options.IncludeDigits && !options.IncludeSpecial && word.Length == 0)
                throw new LocalizedArgumentException(AppErrorCode.NoCharacterSetEnabled);

            var conflicts = Validate(options);
            if (conflicts.Count > 0)
                throw new GeneratorConstraintException(conflicts);

            // The word is verbatim, so whatever it contributes counts against the quotas: asking
            // for at most two digits and embedding "r2d2" cannot mean four.
            var fillerLength = options.Length - word.Length;
            var filler = BuildFiller(options, fillerLength,
                digitsInWord: word.Count(char.IsDigit),
                specialInWord: word.Count(c => Special.Contains(c)));

            if (word.Length == 0)
                return new string(filler);

            var pos = RandomNumberGenerator.GetInt32(fillerLength + 1);
            var result = new char[options.Length];
            Array.Copy(filler, 0, result, 0, pos);
            word.CopyTo(0, result, pos, word.Length);
            Array.Copy(filler, pos, result, pos + word.Length, fillerLength - pos);
            return new string(result);
        }

        /// <summary>
        /// Builds the random part by construction rather than by retrying until it happens to
        /// fit. Rejection sampling was fine while the only requirement was "at least one of
        /// each"; with a quota like "exactly two to three symbols out of twelve" the odds of a
        /// blind draw satisfying it fall off a cliff, and the loop would spin.
        /// </summary>
        private static char[] BuildFiller(PasswordGeneratorOptions options, int length,
                                          int digitsInWord, int specialInWord)
        {
            var buffer = new List<char>(length);

            var digits = Filter(Digits, options);
            var special = Filter(Special, options);
            var letters = (options.IncludeUppercase ? Filter(Uppercase, options) : string.Empty)
                        + (options.IncludeLowercase ? Filter(Lowercase, options) : string.Empty);

            // Without a quota, a class that is switched on gets at least one character: "include
            // symbols" has always meant at least one. With a quota, the quota is the whole
            // answer — taking the larger of the two would make a cap of zero produce one anyway,
            // and a cap of zero is how someone says "none of these" without hunting for the
            // switch that turns the class off.
            var minDigits = (options.LimitDigits ? options.MinDigits
                                                 : options.IncludeDigits ? 1 : 0) - digitsInWord;
            var minSpecial = (options.LimitSpecial ? options.MinSpecial
                                                   : options.IncludeSpecial ? 1 : 0) - specialInWord;

            var maxDigits = (options.LimitDigits ? options.MaxDigits : length) - digitsInWord;
            var maxSpecial = (options.LimitSpecial ? options.MaxSpecial : length) - specialInWord;

            var usedDigits = 0;
            var usedSpecial = 0;

            for (var i = 0; i < minDigits && buffer.Count < length; i++, usedDigits++)
                buffer.Add(Pick(digits));
            for (var i = 0; i < minSpecial && buffer.Count < length; i++, usedSpecial++)
                buffer.Add(Pick(special));

            // Letters carry no quota, so the rest is drawn from whatever still has headroom.
            while (buffer.Count < length)
            {
                var pool = letters;
                if (options.IncludeDigits && usedDigits < maxDigits) pool += digits;
                if (options.IncludeSpecial && usedSpecial < maxSpecial) pool += special;

                // Everything with headroom is exhausted; Validate rules this out, but a caller
                // reaching Generate directly should get a clear failure, not a hang.
                if (pool.Length == 0)
                    throw new GeneratorConstraintException(new[] { GeneratorConflict.MaximumsBelowLength });

                var c = Pick(pool);
                if (Digits.Contains(c)) usedDigits++;
                else if (Special.Contains(c)) usedSpecial++;
                buffer.Add(c);
            }

            var result = buffer.ToArray();
            Shuffle(result);
            return result;
        }

        private static char Pick(string pool) => pool[RandomNumberGenerator.GetInt32(pool.Length)];

        /// <summary>Fisher-Yates over a cryptographic source: the required characters are placed
        /// first, so without this every password would open with its digits.</summary>
        private static void Shuffle(char[] items)
        {
            for (var i = items.Length - 1; i > 0; i--)
            {
                var j = RandomNumberGenerator.GetInt32(i + 1);
                (items[i], items[j]) = (items[j], items[i]);
            }
        }

        public IReadOnlyList<GeneratorConflict> Validate(PasswordGeneratorOptions options)
        {
            var conflicts = new List<GeneratorConflict>();
            var word = options.IncludeWord ?? string.Empty;

            if (word.Length > options.Length)
                conflicts.Add(GeneratorConflict.WordLongerThanLength);

            if (word.Length > 0 && !string.IsNullOrEmpty(ExcludedSet(options)) &&
                word.Any(c => ExcludedSet(options).Contains(c)))
                conflicts.Add(GeneratorConflict.WordContainsExcludedChars);

            var fillerLength = options.Length - word.Length;
            if (fillerLength > 0 && BuildCharPool(options).Length == 0)
                conflicts.Add(GeneratorConflict.NoCharacterSetForFiller);

            // A quota on a class that is switched off is not a tight constraint, it is a
            // contradiction — and silently ignoring it would produce a password the user was
            // told would have two digits and does not.
            if ((options.LimitDigits && !options.IncludeDigits) ||
                (options.LimitSpecial && !options.IncludeSpecial))
                conflicts.Add(GeneratorConflict.LimitOnDisabledSet);

            if ((options.LimitDigits && options.MinDigits > options.MaxDigits) ||
                (options.LimitSpecial && options.MinSpecial > options.MaxSpecial))
                conflicts.Add(GeneratorConflict.CountRangeInverted);

            var minTotal = (options.LimitDigits ? options.MinDigits : 0)
                         + (options.LimitSpecial ? options.MinSpecial : 0);
            if (minTotal > options.Length)
                conflicts.Add(GeneratorConflict.MinimumsExceedLength);

            if (options.LimitDigits && word.Count(char.IsDigit) > options.MaxDigits ||
                options.LimitSpecial && word.Count(c => Special.Contains(c)) > options.MaxSpecial)
                conflicts.Add(GeneratorConflict.WordExceedsCount);

            // With no letters to fall back on, the caps are the whole budget: if they cannot
            // cover the length between them, nothing can.
            var hasLetters = options.IncludeUppercase || options.IncludeLowercase;
            if (!hasLetters && fillerLength > 0)
            {
                var capacity = (options.IncludeDigits ? (options.LimitDigits ? options.MaxDigits : fillerLength) : 0)
                             + (options.IncludeSpecial ? (options.LimitSpecial ? options.MaxSpecial : fillerLength) : 0);
                if (capacity < fillerLength)
                    conflicts.Add(GeneratorConflict.MaximumsBelowLength);
            }

            return conflicts;
        }

        public void ResolveConflicts(PasswordGeneratorOptions options)
        {
            var word = options.IncludeWord ?? string.Empty;

            // Quotas first: the word rules below assume the counts are at least self-consistent.
            if (options.LimitDigits && !options.IncludeDigits) options.LimitDigits = false;
            if (options.LimitSpecial && !options.IncludeSpecial) options.LimitSpecial = false;

            if (options.LimitDigits && options.MinDigits > options.MaxDigits)
                options.MaxDigits = options.MinDigits;
            if (options.LimitSpecial && options.MinSpecial > options.MaxSpecial)
                options.MaxSpecial = options.MinSpecial;

            // Grow the password rather than cut the quotas: the person set those on purpose,
            // and length is the axis that costs nothing to give.
            var minTotal = (options.LimitDigits ? options.MinDigits : 0)
                         + (options.LimitSpecial ? options.MinSpecial : 0);
            if (minTotal > options.Length) options.Length = minTotal;

            if (word.Length == 0)
            {
                EnsureFillable(options);
                return;
            }

            if (word.Length > options.Length)
                options.Length = word.Length;

            // Stop excluding characters that the word itself needs. Ambiguous exclusion is a
            // switch rather than a list, so it is turned off wholesale when the word needs it.
            if (!string.IsNullOrEmpty(options.ExcludeChars))
                options.ExcludeChars = new string(options.ExcludeChars.Where(c => !word.Contains(c)).ToArray());
            if (options.ExcludeAmbiguous && word.Any(c => Ambiguous.Contains(c)))
                options.ExcludeAmbiguous = false;
            if (options.ExcludeProblematic && word.Any(c => Problematic.Contains(c)))
                options.ExcludeProblematic = false;

            if (options.LimitDigits && word.Count(char.IsDigit) > options.MaxDigits)
                options.MaxDigits = word.Count(char.IsDigit);
            if (options.LimitSpecial && word.Count(c => Special.Contains(c)) > options.MaxSpecial)
                options.MaxSpecial = word.Count(c => Special.Contains(c));

            EnsureFillable(options);
        }

        /// <summary>Guarantees something is left to draw from once the word is placed.</summary>
        private static void EnsureFillable(PasswordGeneratorOptions options)
        {
            var word = options.IncludeWord ?? string.Empty;
            var fillerLength = options.Length - word.Length;
            if (fillerLength <= 0) return;

            if (BuildCharPool(options).Length == 0)
                options.IncludeLowercase = true;

            var hasLetters = options.IncludeUppercase || options.IncludeLowercase;
            if (hasLetters) return;

            var capacity = (options.IncludeDigits ? (options.LimitDigits ? options.MaxDigits : fillerLength) : 0)
                         + (options.IncludeSpecial ? (options.LimitSpecial ? options.MaxSpecial : fillerLength) : 0);
            if (capacity < fillerLength) options.IncludeLowercase = true;
        }

        public int CalculateStrength(string password)
        {
            if (string.IsNullOrEmpty(password)) return 0;

            var score = 0;
            if (password.Length >= 8) score++;
            if (password.Length >= 12) score++;
            if (password.Length >= 16) score++;
            if (password.Any(char.IsUpper)) score++;
            if (password.Any(char.IsLower)) score++;
            if (password.Any(char.IsDigit)) score++;
            if (password.Any(c => Special.Contains(c))) score++;
            if (password.Length >= 20) score++;

            return Math.Min(score, 8);
        }

        /// <summary>Everything being kept out: the user's own list, plus the look-alikes and the
        /// awkward punctuation when those switches are on. One place, so validation and
        /// generation cannot disagree.</summary>
        private static string ExcludedSet(PasswordGeneratorOptions options) =>
            (options.ExcludeChars ?? string.Empty)
            + (options.ExcludeAmbiguous ? Ambiguous : string.Empty)
            + (options.ExcludeProblematic ? Problematic : string.Empty);

        private static string Filter(string set, PasswordGeneratorOptions options)
        {
            var excluded = ExcludedSet(options);
            return excluded.Length == 0 ? set : new string(set.Where(c => !excluded.Contains(c)).ToArray());
        }

        private static string BuildCharPool(PasswordGeneratorOptions options)
        {
            var pool = string.Empty;
            if (options.IncludeUppercase) pool += Uppercase;
            if (options.IncludeLowercase) pool += Lowercase;
            if (options.IncludeDigits) pool += Digits;
            if (options.IncludeSpecial) pool += Special;

            var excluded = ExcludedSet(options);
            if (excluded.Length > 0)
                pool = new string(pool.Where(c => !excluded.Contains(c)).ToArray());

            return pool;
        }
    }
}
