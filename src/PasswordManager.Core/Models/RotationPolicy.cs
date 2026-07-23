using System.Text.Json.Serialization;

namespace PasswordManager.Core.Models
{
    public enum RotationUnit { Days, Months }

    /// <summary>Visual state of a rotating secret relative to its expiry.</summary>
    public enum ExpiryStatus { None, Ok, DueSoon, Expired }

    /// <summary>
    /// Optional "change every N days/months" schedule for a secret field. The app only
    /// *reminds* (rotation is manual); automatic rotation is a future app preference.
    /// </summary>
    public class RotationPolicy
    {
        public int Interval { get; set; } = 90;
        public RotationUnit Unit { get; set; } = RotationUnit.Days;

        /// <summary>When the secret was last set/rotated; the countdown starts here.</summary>
        public DateTime LastChanged { get; set; } = DateTime.UtcNow;

        [JsonIgnore]
        public DateTime ExpiresAt => Unit == RotationUnit.Months
            ? LastChanged.AddMonths(Interval)
            : LastChanged.AddDays(Interval);
    }
}
