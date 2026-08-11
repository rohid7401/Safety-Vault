namespace PasswordManager.UI.Components.Shared
{
    /// <summary>
    /// One step of a guided sequence: an icon plus a title/body translation key pair, and
    /// optionally a short bullet list under the body for steps that are advice rather than
    /// description — prose can carry one idea well and four badly.
    /// </summary>
    public sealed record TourStep(string Icon, string TitleKey, string BodyKey, string[]? BulletKeys = null);

    /// <summary>
    /// The guided-tour scripts. The body text for each feature step reuses the same
    /// <c>whatsThis.*</c> strings the old per-page "What's this?" pills used to show — testers
    /// weren't opening those pills, but the explanations themselves were fine, so the tour just
    /// surfaces them up front instead of hiding them behind a tap.
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
        /// Shown once before the sign-in card, on the very first launch — <em>before</em> there is
        /// an account, which is the whole point. The advice on picking a passphrase used to live
        /// at step 5 of a page reachable only from the menu, i.e. only after the passphrase had
        /// already been chosen. The same bullets back the (i) beside the passphrase field, so the
        /// help is also there at the moment of typing and not only 40 seconds earlier.
        /// </summary>
        public static readonly TourStep[] IntroSteps =
        {
            new("lock-keyhole", "intro.vault.title", "intro.vault.body"),
            new("key", "intro.passphrase.title", "intro.passphrase.body"),
            // Its own step rather than a footnote on the previous one: it is the single fact that
            // changes what someone does next, and it cannot be walked back later.
            new("alert", "intro.norecovery.title", "intro.norecovery.body"),
            new("shield-check", "intro.choose.title", "intro.choose.body", PassphraseTipKeys),
            new("check", "intro.ready.title", "intro.ready.body"),
        };

        /// <summary>
        /// How to pick a passphrase. Shared by the intro step and the (i) on the sign-up form so
        /// the two can never drift into giving different advice.
        /// </summary>
        public static readonly string[] PassphraseTipKeys =
        {
            "intro.tip.length",
            "intro.tip.personal",
            "intro.tip.reuse",
            "intro.tip.storage",
        };
    }
}
