using PasswordManager.UI.Localization;

namespace PasswordManager.UI.Components.Shared
{
    /// <summary>
    /// "today" / "3 days ago" / "2 months ago" for entry timestamps. Extracted from VaultPage
    /// once the notes and cards indexes needed the same phrasing — three copies of this would
    /// have drifted apart, and the rounding is the sort of thing that only looks wrong when two
    /// screens disagree about the same date.
    /// </summary>
    public static class RelativeTime
    {
        public static string Ago(Loc l, DateTime utc)
        {
            var days = (int)(DateTime.UtcNow - utc).TotalDays;
            if (days <= 0) return l["vault.ago.today"];
            if (days == 1) return l["vault.ago.yesterday"];
            if (days < 30) return l.Format("vault.ago.days", days);
            if (days < 365) return l.Format("vault.ago.months", days / 30);
            return l.Format("vault.ago.years", days / 365);
        }
    }
}
