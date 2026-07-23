using System.Text.Json;
using PasswordManager.Core.Models;
using Xunit;

namespace PasswordManager.Tests.Models
{
    /// <summary>
    /// Tanda 2 — the flexible credential model: arbitrary typed fields per credential,
    /// single-slot rotation history, expiry status, and polymorphic serialization.
    /// </summary>
    public class ServiceEntryModelTests
    {
        private static EncryptedField Enc(string marker) =>
            new() { CipherText = marker, Nonce = "n", Tag = "t" };

        // ─── Serialization ───────────────────────────────────────────────────

        [Fact]
        public void ServiceEntry_RoundTripsThroughPolymorphicJson()
        {
            var vault = new VaultData();
            vault.Entries.Add(new ServiceEntry
            {
                Site = "Google",
                Grouped = true,
                Credentials =
                {
                    new Credential
                    {
                        Label = "Personal",
                        Fields =
                        {
                            new CredentialField { Type = CredentialFieldType.Email, PlainValue = "a@gmail.com" },
                            new CredentialField
                            {
                                Type = CredentialFieldType.Password,
                                IsSecret = true,
                                SecretValue = Enc("pw"),
                                Rotation = new RotationPolicy { Interval = 3, Unit = RotationUnit.Months },
                            },
                            new CredentialField
                            {
                                Type = CredentialFieldType.TwoFactor,
                                IsSecret = true,
                                SecretValue = Enc("2fa"),
                                TwoFactorKind = TwoFactorKind.Hotp,
                                HotpCounter = 7,
                            },
                        },
                    },
                },
            });

            var json = JsonSerializer.Serialize(vault, new JsonSerializerOptions { WriteIndented = true });
            var back = JsonSerializer.Deserialize<VaultData>(json)!;

            var entry = Assert.IsType<ServiceEntry>(Assert.Single(back.Entries));
            Assert.Equal("Google", entry.Site);
            var cred = Assert.Single(entry.Credentials);
            Assert.Equal("Personal", cred.Label);
            Assert.Equal(3, cred.Fields.Count);

            var pw = cred.Fields[1];
            Assert.Equal(CredentialFieldType.Password, pw.Type);
            Assert.Equal("pw", pw.SecretValue!.CipherText);
            Assert.Equal(RotationUnit.Months, pw.Rotation!.Unit);
            Assert.Equal(3, pw.Rotation.Interval);

            var tfa = cred.Fields[2];
            Assert.Equal(TwoFactorKind.Hotp, tfa.TwoFactorKind);
            Assert.Equal(7, tfa.HotpCounter);
        }

        [Fact]
        public void ServiceEntry_CoexistsWithOtherEntryTypes()
        {
            var vault = new VaultData();
            vault.Entries.Add(new ServiceEntry { Site = "new.com" });
            vault.Entries.Add(new SecureNote { Label = "note" });

            var json = JsonSerializer.Serialize(vault);
            var back = JsonSerializer.Deserialize<VaultData>(json)!;

            Assert.Single(back.Entries.OfType<ServiceEntry>());
            Assert.Single(back.Entries.OfType<SecureNote>());
        }

        // ─── Rotation history (single slot) ──────────────────────────────────

        [Fact]
        public void SetSecret_WithRotation_KeepsOnlyTheImmediatelyPreviousValue()
        {
            var field = new CredentialField
            {
                Type = CredentialFieldType.Password,
                IsSecret = true,
                Rotation = new RotationPolicy { Interval = 30 },
                SecretValue = Enc("v1"),
            };

            field.SetSecret(Enc("v2"));
            Assert.Equal("v2", field.SecretValue!.CipherText);
            Assert.Equal("v1", field.PreviousSecret!.CipherText);

            field.SetSecret(Enc("v3"));
            Assert.Equal("v3", field.SecretValue!.CipherText);
            Assert.Equal("v2", field.PreviousSecret!.CipherText); // v1 is gone
        }

        [Fact]
        public void SetSecret_WithoutRotation_DoesNotKeepPrevious()
        {
            var field = new CredentialField
            {
                Type = CredentialFieldType.Password,
                IsSecret = true,
                SecretValue = Enc("v1"),
            };

            field.SetSecret(Enc("v2"));
            Assert.Equal("v2", field.SecretValue!.CipherText);
            Assert.Null(field.PreviousSecret);
        }

        [Fact]
        public void SetSecret_WithRotation_RestartsTheRotationClock()
        {
            var field = new CredentialField
            {
                Type = CredentialFieldType.Password,
                Rotation = new RotationPolicy { Interval = 30, LastChanged = DateTime.UtcNow.AddDays(-100) },
                SecretValue = Enc("v1"),
            };

            field.SetSecret(Enc("v2"));
            Assert.True(field.Rotation!.LastChanged > DateTime.UtcNow.AddMinutes(-1));
        }

        // ─── Expiry status ───────────────────────────────────────────────────

        [Fact]
        public void GetExpiryStatus_ReflectsTimeUntilExpiry()
        {
            var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            CredentialField Field(int lastChangedDaysAgo) => new()
            {
                Rotation = new RotationPolicy { Interval = 30, Unit = RotationUnit.Days, LastChanged = now.AddDays(-lastChangedDaysAgo) },
            };

            Assert.Equal(ExpiryStatus.Ok, Field(5).GetExpiryStatus(now));       // expires in 25d
            Assert.Equal(ExpiryStatus.DueSoon, Field(20).GetExpiryStatus(now)); // expires in 10d (<14)
            Assert.Equal(ExpiryStatus.Expired, Field(40).GetExpiryStatus(now)); // expired 10d ago
        }

        [Fact]
        public void GetExpiryStatus_NoRotation_IsNone()
        {
            var field = new CredentialField { Type = CredentialFieldType.Password };
            Assert.Equal(ExpiryStatus.None, field.GetExpiryStatus(DateTime.UtcNow));
        }

        // ─── Field-type defaults ─────────────────────────────────────────────

        [Theory]
        [InlineData(CredentialFieldType.Password, true)]
        [InlineData(CredentialFieldType.Pin, true)]
        [InlineData(CredentialFieldType.TwoFactor, true)]
        [InlineData(CredentialFieldType.Email, false)]
        [InlineData(CredentialFieldType.Username, false)]
        [InlineData(CredentialFieldType.Phone, false)]
        [InlineData(CredentialFieldType.Text, false)]
        public void IsSecretByDefault_MatchesFieldSensitivity(CredentialFieldType type, bool expected)
        {
            Assert.Equal(expected, CredentialField.IsSecretByDefault(type));
        }
    }
}
