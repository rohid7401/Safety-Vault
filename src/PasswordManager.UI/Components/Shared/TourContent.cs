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
    /// <summary>
    /// One stop of the spotlight tour: which element on screen to cut out of the veil, how much
    /// air to leave around it, and what the bubble says.
    /// </summary>
    /// <param name="Targets">
    /// <c>data-tour</c> names to highlight. More than one means the cutout is their union, and
    /// anything not currently rendered is skipped — which is how a stop survives a layout that
    /// hides one of them. At 900px and wider the app drops the menu button and pins the drawer
    /// open as a sidebar, so the menu stop names both and gets whichever exists.
    /// </param>
    /// <param name="Pad">Air between the element and the cutout's edge.</param>
    /// <param name="Radius">The element's own corner radius. The cutout uses Radius + Pad so the
    /// two curves stay concentric instead of the outer one looking flat.</param>
    /// <param name="OpensDrawer">Set on a stop whose target lives inside the navigation drawer:
    /// the drawer has to be open and settled before the rectangle means anything.</param>
    public sealed record TourStop(
        string[] Targets, int Pad, int Radius, string TitleKey, string BodyKey, string MissKey,
        bool OpensDrawer = false);

    public static class TourContent
    {
        /// <summary>
        /// Five stops over the dashboard, and the last one opens the menu to show the way out.
        /// </summary>
        /// <remarks>
        /// It was nine cards in a centred carousel that described modules without pointing at any
        /// of them. Generator and Import/Export lost the separate stops they had in the first
        /// draft: beside Audit they were three identical tiles in the same group taking the same
        /// rectangle, which is the carousel again with a cutout on top. Both are still inside the
        /// Tools cutout and still named in its text — what they lose is a stop of their own.
        ///
        /// The last stop has two beats, the button and what the button opens. It stays one stop
        /// because it is one gesture, so the counter must not promise a sixth.
        /// </remarks>
        public static readonly TourStop[] Stops =
        {
            new(["stats"], 10, 8, "tour.stats.title", "tour.stats.body", "tour.stats.miss"),
            new(["group-vault"], 8, 14, "tour.vault.title", "tour.vault.body", "tour.vault.miss"),
            new(["group-tools"], 8, 14, "tour.tools.title", "tour.tools.body", "tour.tools.miss"),
            new(["tile-audit"], 8, 14, "tour.audit.title", "tour.audit.body", "tour.audit.miss"),
            // Two names, one stop: on a phone only the button exists, on a wide window only the
            // sidebar does. Naming just the button left this stop reporting "not found" on every
            // desktop run, since the button is display:none there.
            new(["menu", "drawer"], 6, 8, "tour.menu.title", "tour.menu.body", "tour.menu.miss"),
        };

        /// <summary>The second beat of the last stop, once the drawer it opened has settled.</summary>
        public static readonly TourStop MenuBeat =
            new(["lock"], 8, 8, "tour.lock.title", "tour.lock.body", "tour.lock.miss", OpensDrawer: true);

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
