using PasswordManager.UI.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    /// <summary>
    /// The vault holds decrypted secrets in memory, so it must close once the app has been out
    /// of sight long enough. These tests pin both halves of that: the grace period really does
    /// let a quick trip to another app through, and neither clock can be used to hide how long
    /// the app was actually away.
    /// </summary>
    public class VaultAutoLockTests
    {
        private static readonly TimeSpan Grace = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan ExcursionGrace = TimeSpan.FromMinutes(5);
        private static readonly DateTimeOffset Start = new(2026, 8, 1, 12, 0, 0, TimeSpan.Zero);

        /// <summary>Drives both clocks independently so a test can suspend one and not the other.</summary>
        private sealed class TestClock
        {
            public DateTimeOffset Wall = Start;
            public long MonotonicMs = 1_000_000;

            public AutoLockClock Read() => new(Wall, MonotonicMs);

            public void Advance(TimeSpan by)
            {
                Wall += by;
                MonotonicMs += (long)by.TotalMilliseconds;
            }
        }

        private static (VaultAutoLock Lock, TestClock Clock, Func<int> Requests) Build()
        {
            var clock = new TestClock();
            var autoLock = new VaultAutoLock(Grace, ExcursionGrace, clock.Read);
            var count = 0;
            autoLock.LockRequested += () => count++;
            return (autoLock, clock, () => count);
        }

        [Fact]
        public void ReturningWithinGracePeriod_DoesNotLock()
        {
            var (autoLock, clock, requests) = Build();

            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromSeconds(25)); // popped out to paste a password
            autoLock.OnForeground();

            Assert.Equal(0, requests());
        }

        [Fact]
        public void ReturningAfterGracePeriod_Locks()
        {
            var (autoLock, clock, requests) = Build();

            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromSeconds(31));
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void ReturningExactlyAtGracePeriod_Locks()
        {
            var (autoLock, clock, requests) = Build();

            autoLock.OnBackground();
            clock.Advance(Grace);
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void ForegroundWithoutPriorBackground_DoesNotLock()
        {
            // First launch, and any spurious resume: there is no away-time to judge.
            var (autoLock, clock, requests) = Build();

            clock.Advance(TimeSpan.FromHours(5));
            autoLock.OnForeground();

            Assert.Equal(0, requests());
        }

        [Fact]
        public void SecondForeground_WithoutLeavingAgain_DoesNotLockTwice()
        {
            var (autoLock, clock, requests) = Build();

            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromMinutes(10));
            autoLock.OnForeground();
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void RepeatedBackground_KeepsTheEarliestMark()
        {
            // A duplicate background callback must not restart the countdown, or the app could
            // be kept unlocked indefinitely by whatever is emitting them.
            var (autoLock, clock, requests) = Build();

            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromSeconds(20));
            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromSeconds(20)); // 40s since the first mark, 20s since the second
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void WallClockMovedBackwards_StillLocks()
        {
            // Winding the device clock back would otherwise make a long absence look instant.
            var (autoLock, clock, requests) = Build();

            autoLock.OnBackground();
            clock.MonotonicMs += (long)TimeSpan.FromMinutes(10).TotalMilliseconds;
            clock.Wall -= TimeSpan.FromHours(2);
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void MonotonicClockFrozenBySuspend_StillLocks()
        {
            // The monotonic clock does not tick while the device is suspended, so a phone left
            // asleep overnight reports almost no elapsed time on that clock alone.
            var (autoLock, clock, requests) = Build();

            autoLock.OnBackground();
            clock.Wall += TimeSpan.FromHours(8);
            clock.MonotonicMs += 40; // a few ticks either side of the suspend
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void BothClocksStalled_DoesNotLock()
        {
            // Guards the maximum-of-two rule from degenerating into "lock whenever unsure".
            var (autoLock, _, requests) = Build();

            autoLock.OnBackground();
            autoLock.OnForeground();

            Assert.Equal(0, requests());
        }

        // ─── App-initiated picker excursions ─────────────────────────────────

        [Fact]
        public void BrowsingForAFile_PastTheNormalGrace_DoesNotLock()
        {
            // The whole point: picking a file takes longer than 30s and must survive it.
            var (autoLock, clock, requests) = Build();

            using (autoLock.ExpectPickerExcursion())
            {
                autoLock.OnBackground();
                clock.Advance(TimeSpan.FromMinutes(2));
                autoLock.OnForeground();
            }

            Assert.Equal(0, requests());
        }

        [Fact]
        public void AbandoningThePicker_PastTheExcursionGrace_StillLocks()
        {
            // The allowance is generous, not unlimited — walking away mid-pick still locks.
            var (autoLock, clock, requests) = Build();

            using (autoLock.ExpectPickerExcursion())
            {
                autoLock.OnBackground();
                clock.Advance(TimeSpan.FromMinutes(6));
                autoLock.OnForeground();
            }

            Assert.Equal(1, requests());
        }

        [Fact]
        public void OnePickerSession_PausingAndResumingTwice_IsStillCovered()
        {
            // Android can pause/resume more than once around a single picker, so the excursion
            // must not be spent by the first resume.
            var (autoLock, clock, requests) = Build();

            using (autoLock.ExpectPickerExcursion())
            {
                autoLock.OnBackground();
                clock.Advance(TimeSpan.FromMinutes(1));
                autoLock.OnForeground();

                autoLock.OnBackground();
                clock.Advance(TimeSpan.FromMinutes(1));
                autoLock.OnForeground();
            }

            Assert.Equal(0, requests());
        }

        [Fact]
        public void AfterThePickerReturns_TheNormalGraceIsBackImmediately()
        {
            var (autoLock, clock, requests) = Build();

            using (autoLock.ExpectPickerExcursion()) { /* picker opened and returned */ }

            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromSeconds(31));
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void ALeakedExcursion_AgesOutAndStopsSuppressingTheLock()
        {
            // The scenario the design exists to survive: a scope that is never disposed. It must
            // not leave the vault permanently unlocked — once the arming is older than the
            // excursion allowance it stops counting, and the normal grace applies again.
            var (autoLock, clock, requests) = Build();

            _ = autoLock.ExpectPickerExcursion(); // deliberately never disposed

            clock.Advance(TimeSpan.FromMinutes(6)); // the arming ages out
            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromSeconds(31));
            autoLock.OnForeground();

            Assert.Equal(1, requests());
        }

        [Fact]
        public void NestedExcursions_OnlyEndWhenTheLastOneCloses()
        {
            var (autoLock, clock, requests) = Build();

            var outer = autoLock.ExpectPickerExcursion();
            var inner = autoLock.ExpectPickerExcursion();
            inner.Dispose();

            // The outer scope is still open, so the generous allowance must still apply.
            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromMinutes(2));
            autoLock.OnForeground();
            Assert.Equal(0, requests());

            outer.Dispose();

            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromSeconds(31));
            autoLock.OnForeground();
            Assert.Equal(1, requests());
        }

        [Fact]
        public void DisposingAnExcursionTwice_DoesNotEndASiblingEarly()
        {
            var (autoLock, clock, requests) = Build();

            var first = autoLock.ExpectPickerExcursion();
            var second = autoLock.ExpectPickerExcursion();
            first.Dispose();
            first.Dispose(); // double dispose must be inert

            autoLock.OnBackground();
            clock.Advance(TimeSpan.FromMinutes(2));
            autoLock.OnForeground();

            Assert.Equal(0, requests());
            second.Dispose();
        }
    }
}
