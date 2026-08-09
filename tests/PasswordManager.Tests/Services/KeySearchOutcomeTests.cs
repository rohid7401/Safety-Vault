using PasswordManager.UI.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>
    /// Which answer wins when several directories are asked at once, and what the user is warned
    /// about. Getting this wrong is silent: the app would hand over a key that looks as trustworthy
    /// as any other.
    /// </summary>
    public class KeySearchOutcomeTests
    {
        private static readonly KeyServerSource Verifying =
            new("keys.openpgp.org", "https://example/{0}", VerifiesOwnership: true);
        private static readonly KeyServerSource AlsoVerifying =
            new("keys.mailvelope.com", "https://example2/{0}", VerifiesOwnership: true);
        private static readonly KeyServerSource Open =
            new("keyserver.ubuntu.com", "https://example3/{0}", VerifiesOwnership: false);

        private static KeySearchOutcome Outcome(params KeyServerHit[] hits) =>
            new(hits, Array.Empty<string>());

        [Fact]
        public void NoHits_IsNotFound()
        {
            var outcome = Outcome();

            Assert.False(outcome.Found);
            Assert.Null(outcome.Best);
            Assert.False(outcome.OnlyFromUnverifiedSources);
        }

        [Fact]
        public void ThePreferredAnswerIsTheFirstListed_NotWhoeverRepliedFirst()
        {
            // Hits arrive in Sources order, so the same search twice gives the same key rather
            // than depending on which server happened to be quick that second.
            var outcome = Outcome(
                new KeyServerHit(Verifying, "key-from-verifying"),
                new KeyServerHit(Open, "key-from-open"));

            Assert.Equal("key-from-verifying", outcome.Best!.Armored);
        }

        [Fact]
        public void AKeyOnlyOnAnOpenDirectory_IsFlagged()
        {
            // Anyone can upload a key claiming any address there, so where it was found proves
            // nothing — the user has to lean on the fingerprint.
            var outcome = Outcome(new KeyServerHit(Open, "key"));

            Assert.True(outcome.Found);
            Assert.True(outcome.OnlyFromUnverifiedSources);
        }

        [Fact]
        public void AKeyOnAVerifyingDirectory_IsNotFlagged()
        {
            Assert.False(Outcome(new KeyServerHit(Verifying, "key")).OnlyFromUnverifiedSources);

            // Still not flagged when an open directory also has it: one server did check.
            Assert.False(Outcome(
                new KeyServerHit(Verifying, "key"),
                new KeyServerHit(Open, "key")).OnlyFromUnverifiedSources);
        }

        [Fact]
        public void EveryDirectoryThatHadTheKeyIsReported()
        {
            var outcome = Outcome(
                new KeyServerHit(Verifying, "key"),
                new KeyServerHit(AlsoVerifying, "key"),
                new KeyServerHit(Open, "key"));

            Assert.Equal(
                new[] { "keys.openpgp.org", "keys.mailvelope.com", "keyserver.ubuntu.com" },
                outcome.FoundOn);
        }

        [Fact]
        public void ServersThatNeverAnswered_AreKept()
        {
            // "Not found" means less when a directory was down; the caller shows that.
            var outcome = new KeySearchOutcome(
                Array.Empty<KeyServerHit>(), new[] { "keyserver.ubuntu.com" });

            Assert.False(outcome.Found);
            Assert.Equal(new[] { "keyserver.ubuntu.com" }, outcome.Unreachable);
        }

        [Fact]
        public void TheConfiguredSourcesPutVerifyingDirectoriesFirst()
        {
            // The order is the preference, so it has to hold in the real list and not only here.
            var sources = KeyServerService.Sources;
            var lastVerifying = sources.Select((s, i) => (s, i)).Last(x => x.s.VerifiesOwnership).i;
            var firstOpen = sources.Select((s, i) => (s, i)).FirstOrDefault(x => !x.s.VerifiesOwnership).i;

            Assert.Contains(sources, s => s.VerifiesOwnership);
            Assert.True(lastVerifying < firstOpen);
        }

        [Fact]
        public void EverySourceIsHttpsAndHasAPlaceholderForTheAddress()
        {
            // A missing placeholder would silently search for the literal "{0}" on every lookup.
            Assert.All(KeyServerService.Sources, s =>
            {
                Assert.StartsWith("https://", s.SearchUrlTemplate, StringComparison.Ordinal);
                Assert.Contains("{0}", s.SearchUrlTemplate, StringComparison.Ordinal);
            });
        }

        [Fact]
        public void SourceNamesAreDistinct()
        {
            var names = KeyServerService.Sources.Select(s => s.Name).ToList();
            Assert.Equal(names.Count, names.Distinct().Count());
        }
    }
}
