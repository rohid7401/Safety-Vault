using PasswordManager.UI.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>
    /// The catalogue is the only description of what the app can be configured to do, so its
    /// defaults and its offered choices have to agree with each other and with the code that
    /// still hardcodes a fallback.
    /// </summary>
    public class AppSettingsCatalogTests
    {
        [Fact]
        public void EveryDefaultIsOneOfTheOfferedChoices()
        {
            // A default outside the list renders a picker showing something the user never chose
            // and cannot get back to once they change it.
            Assert.Contains(AppSettingsCatalog.ClipboardClearSeconds.Default, AppSettingsCatalog.ClipboardChoices);
            Assert.Contains(AppSettingsCatalog.AutoLockGraceSeconds.Default, AppSettingsCatalog.AutoLockChoices);
            Assert.Contains(AppSettingsCatalog.RotationDefaultDays.Default, AppSettingsCatalog.RotationChoices);
        }

        [Fact]
        public void TheDefaultsMatchWhatTheServicesFallBackTo()
        {
            // Both services keep a hardcoded fallback for when no vault is open. If it drifted
            // from the catalogue, the app would behave one way before sign-in and another after.
            Assert.Equal(
                (int)SecureClipboardService.DefaultClearAfter.TotalSeconds,
                AppSettingsCatalog.ClipboardClearSeconds.Default);
            Assert.Equal(
                (int)VaultAutoLock.DefaultGracePeriod.TotalSeconds,
                AppSettingsCatalog.AutoLockGraceSeconds.Default);
        }

        [Fact]
        public void TheClipboardIsAlwaysClearedEventually()
        {
            // Zero would mean "never clear", which is the one thing this feature must not offer.
            Assert.All(AppSettingsCatalog.ClipboardChoices, s => Assert.True(s > 0));
        }

        [Fact]
        public void AutoLockOffersNoWayToTurnItOff()
        {
            // Zero here is "lock as soon as you leave", the strictest option — not "never". The
            // longest allowance is capped, because a phone left on a table is the threat.
            Assert.All(AppSettingsCatalog.AutoLockChoices, s => Assert.InRange(s, 0, 300));
        }

        [Fact]
        public void RotationIntervalsAreAllUsable()
        {
            Assert.All(AppSettingsCatalog.RotationChoices, d => Assert.True(d > 0));
        }

        [Fact]
        public void SettingKeysAreDistinct()
        {
            // Two settings sharing a key would silently overwrite each other in the vault.
            var keys = new[]
            {
                AppSettingsCatalog.ClipboardClearSeconds.Key,
                AppSettingsCatalog.AutoLockGraceSeconds.Key,
                AppSettingsCatalog.RotationDefaultDays.Key,
            };

            Assert.Equal(keys.Length, keys.Distinct().Count());
        }

        [Fact]
        public void AStoredValueThatNoLongerParses_FallsBackToTheDefault()
        {
            // A preference written by another build must never be able to stop a screen rendering.
            Assert.False(AppSettingsCatalog.ClipboardClearSeconds.TryParse("not a number", out _));
        }

        [Fact]
        public void NoLevelOneSettingIsBehindAPaidTier()
        {
            Assert.False(AppSettingsCatalog.ClipboardClearSeconds.RequiresPaidTier);
            Assert.False(AppSettingsCatalog.AutoLockGraceSeconds.RequiresPaidTier);
            Assert.False(AppSettingsCatalog.RotationDefaultDays.RequiresPaidTier);
        }
    }
}
