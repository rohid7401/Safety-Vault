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
            new("key", "nav.keys", "whatsThis.keys"),
            new("file", "nav.encryptFiles", "whatsThis.encrypt-file"),
            new("folder", "nav.encryptDirs", "whatsThis.encrypt-directory"),
        };
    }
}
