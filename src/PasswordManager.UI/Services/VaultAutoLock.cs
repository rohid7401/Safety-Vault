namespace PasswordManager.UI.Services
{
    /// <summary>
    /// A point in time read from both clocks at once. Elapsed time is measured as the larger of
    /// the two deltas, because each clock can be fooled on its own:
    /// <list type="bullet">
    /// <item>the wall clock can be moved backwards (by the user, or by an attacker holding the
    /// device) to make it look as though no time has passed;</item>
    /// <item>the monotonic clock does not advance while the device is suspended, so a phone left
    /// asleep overnight can report only seconds of elapsed time.</item>
    /// </list>
    /// Taking the maximum means hiding elapsed time requires defeating both at once.
    /// </summary>
    public readonly record struct AutoLockClock(DateTimeOffset Wall, long MonotonicMs)
    {
        public static AutoLockClock Now() => new(DateTimeOffset.UtcNow, Environment.TickCount64);

        public TimeSpan Since(AutoLockClock earlier)
        {
            var wall = Wall - earlier.Wall;
            var monotonic = TimeSpan.FromMilliseconds(MonotonicMs - earlier.MonotonicMs);
            var elapsed = wall > monotonic ? wall : monotonic;
            return elapsed < TimeSpan.Zero ? TimeSpan.Zero : elapsed;
        }
    }

    /// <summary>
    /// Decides whether the vault should be locked after the app has spent time in the background.
    /// The vault holds decrypted secrets in memory, so leaving it open once the app is out of
    /// sight would let anyone who picks up the unlocked phone read everything.
    ///
    /// <para>A short grace period keeps the common case usable: stepping out to paste a password
    /// into another app and coming straight back should not force a re-unlock.</para>
    ///
    /// <para>The decision is evaluated when the app returns to the foreground rather than on a
    /// timer while it is away. Android throttles and may never run background timers, so a timer
    /// would be unreliable exactly when it mattered; checking on return is deterministic, and
    /// returning to the app is the only moment at which the secrets could actually be read.</para>
    ///
    /// <para>Deliberately knows nothing about <see cref="AppState"/>: this type answers only
    /// "was the app away long enough?", leaving the caller to decide what locking means.</para>
    /// </summary>
    public sealed class VaultAutoLock
    {
        /// <summary>How long the app may stay in the background before the vault is locked.</summary>
        public static readonly TimeSpan DefaultGracePeriod = TimeSpan.FromSeconds(30);

        /// <summary>
        /// The grace period that applies instead while the app is waiting on a system picker it
        /// opened itself. Browsing to a file is a deliberate errand the user will come back from,
        /// but it routinely takes longer than <see cref="DefaultGracePeriod"/> — without this,
        /// importing a file would usually end in a locked vault and a half-filled form thrown away.
        /// </summary>
        public static readonly TimeSpan DefaultExcursionGracePeriod = TimeSpan.FromMinutes(5);

        private readonly TimeSpan _gracePeriod;
        private readonly TimeSpan _excursionGracePeriod;
        private readonly Func<AutoLockClock> _clock;

        private AutoLockClock? _leftForegroundAt;
        private AutoLockClock? _excursionArmedAt;
        private int _openExcursions;

        /// <summary>
        /// Raised on return to the foreground when the app was away for at least the grace
        /// period. Raised on whichever thread reported the lifecycle change, so a UI subscriber
        /// must marshal before touching component state.
        /// </summary>
        public event Action? LockRequested;

        public VaultAutoLock()
            : this(DefaultGracePeriod, DefaultExcursionGracePeriod, AutoLockClock.Now) { }

        /// <summary>Test seam: lets a test drive the clock and shorten the grace periods.</summary>
        public VaultAutoLock(TimeSpan gracePeriod, TimeSpan excursionGracePeriod, Func<AutoLockClock> clock)
        {
            _gracePeriod = gracePeriod;
            _excursionGracePeriod = excursionGracePeriod;
            _clock = clock;
        }

        /// <summary>
        /// Marks that the app is about to hand off to a system picker and expects to be resumed.
        /// Dispose the returned scope once the picker returns.
        ///
        /// <para>Deliberately does <em>not</em> switch locking off. It only swaps the short grace
        /// period for <see cref="DefaultExcursionGracePeriod"/>, and only for as long as the scope
        /// itself is that recent. A scope that leaks — never disposed because of a crash or a code
        /// path nobody thought about — therefore cannot leave the vault unprotected: it stops
        /// being honoured on its own once it ages out, and even while honoured it caps exposure at
        /// minutes rather than disabling the lock outright.</para>
        /// </summary>
        public IDisposable ExpectPickerExcursion()
        {
            _excursionArmedAt = _clock();
            _openExcursions++;
            return new ExcursionScope(this);
        }

        private void EndExcursion()
        {
            if (--_openExcursions > 0) return;
            _openExcursions = 0;
            _excursionArmedAt = null;
        }

        /// <summary>The excursion allowance applies only while the arming is itself recent.</summary>
        private TimeSpan GracePeriodAt(AutoLockClock now) =>
            _excursionArmedAt is { } armed && now.Since(armed) <= _excursionGracePeriod
                ? _excursionGracePeriod
                : _gracePeriod;

        private sealed class ExcursionScope : IDisposable
        {
            private VaultAutoLock? _owner;

            public ExcursionScope(VaultAutoLock owner) => _owner = owner;

            public void Dispose()
            {
                // Null out first: a double dispose must not decrement the count twice and end a
                // sibling picker's excursion early.
                var owner = _owner;
                _owner = null;
                owner?.EndExcursion();
            }
        }

        public void OnBackground()
        {
            // Never overwrite an existing mark. If a second background arrives without an
            // intervening foreground, the earlier timestamp is the honest one — keeping it can
            // only make the app more likely to lock, never less.
            _leftForegroundAt ??= _clock();
        }

        public void OnForeground()
        {
            var leftAt = _leftForegroundAt;
            _leftForegroundAt = null;

            if (leftAt is null) return;

            // The excursion is left standing rather than consumed here: one picker session can
            // pause and resume the app more than once, and the scope's own age is what bounds it.
            var now = _clock();
            if (now.Since(leftAt.Value) < GracePeriodAt(now)) return;

            LockRequested?.Invoke();
        }
    }
}
