namespace PasswordManager.UI.Components.Shared
{
    /// <summary>One step of the guided tour: an icon plus a title/body translation key pair.</summary>
    public sealed record TourStep(string Icon, string TitleKey, string BodyKey);

    /// <summary>
    /// The guided-tour script, shared by the first-run overlay (<see cref="OnboardingTour"/>)
    /// and the revisit page (<c>WalkthroughPage</c>). The body text for each feature step
    /// reuses the same <c>whatsThis.*</c> strings the old per-page "What's this?" pills used
    /// to show — testers weren't opening those pills, but the explanations themselves were
    /// fine, so the tour just surfaces them up front instead of hiding them behind a tap.
    /// </summary>
    public static class TourContent
    {
        public static readonly TourStep[] Steps =
        {
            new("lock-keyhole", "tour.welcome.title", "tour.welcome.body"),
            new("lock", "nav.passwords", "whatsThis.passwords"),
            new("note", "nav.notes", "whatsThis.notes"),
            new("card", "nav.cards", "whatsThis.cards"),
            new("refresh", "nav.generator", "whatsThis.generator"),
            new("shield", "nav.audit", "whatsThis.audit"),
            new("swap", "nav.importExport", "whatsThis.import-export"),
            new("trash", "nav.data", "whatsThis.data"),
            // One step for the whole PGP module: it used to be three, which made an optional
            // extra look like three core features and stretched the first-run tour.
            new("key", "nav.pgp", "whatsThis.pgp"),
        };

        /// <summary>
        /// Shown in place of the "Your keys" card the first time someone opens Key Management
        /// without a PGP identity yet: testers who didn't know what PGP was would land on a
        /// bare "create identity" form with no idea why they needed one. This walks through what
        /// the pair is for before the create button is ever reachable.
        /// </summary>
        public static readonly TourStep[] PgpSteps =
        {
            new("key", "pgpTour.what.title", "pgpTour.what.body"),
            new("shield-check", "pgpTour.use.title", "pgpTour.use.body"),
            new("lock-keyhole", "pgpTour.pair.title", "pgpTour.pair.body"),
            new("check", "pgpTour.ready.title", "pgpTour.ready.body"),
        };
    }
}
