using System.Text.Json;
using PasswordManager.Core.Models;
using Xunit;

namespace PasswordManager.Tests.Models
{
    public class CredentialFieldTests
    {
        /// <summary>
        /// The vault serializer registers no <c>JsonStringEnumConverter</c>, so these enum members
        /// persist as bare integers inside every vault already on a user's device. Inserting a
        /// member ahead of an existing one renumbers it and silently retypes stored fields — a
        /// vault holding a 6 written as "Text" would read back as whatever now occupies 6. This
        /// test pins the wire values so that mistake fails here instead of on someone's phone.
        /// </summary>
        [Theory]
        [InlineData(CredentialFieldType.Email, 0)]
        [InlineData(CredentialFieldType.Username, 1)]
        [InlineData(CredentialFieldType.Password, 2)]
        [InlineData(CredentialFieldType.Pin, 3)]
        [InlineData(CredentialFieldType.Phone, 4)]
        [InlineData(CredentialFieldType.TwoFactor, 5)]
        [InlineData(CredentialFieldType.Text, 6)]
        [InlineData(CredentialFieldType.Web, 7)]
        public void FieldType_HasStableStoredValue(CredentialFieldType type, int stored)
            => Assert.Equal(stored, (int)type);

        [Fact]
        public void Web_IsNotSecretByDefault()
            => Assert.False(CredentialField.IsSecretByDefault(CredentialFieldType.Web));

        [Fact]
        public void SetSecret_StampsLastChanged()
        {
            var field = new CredentialField { Type = CredentialFieldType.Password, IsSecret = true };
            Assert.Null(field.LastChanged);

            field.SetSecret(new EncryptedField());

            Assert.NotNull(field.LastChanged);
            Assert.InRange(field.LastChanged!.Value, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(1));
        }

        /// <summary>
        /// A credential written before <see cref="CredentialField.LastChanged"/> existed carries no
        /// such property. Reading it must leave the date unknown rather than defaulting to "now",
        /// which would tell every tester their years-old passwords changed the day they updated.
        /// </summary>
        [Fact]
        public void Deserializing_FieldWithoutLastChanged_LeavesItNull()
        {
            const string storedBeforeTheFeature = """
                { "Type": 2, "IsSecret": true, "PlainValue": "" }
                """;

            var field = JsonSerializer.Deserialize<CredentialField>(storedBeforeTheFeature)!;

            Assert.Null(field.LastChanged);
            Assert.Equal(CredentialFieldType.Password, field.Type);
        }
    }
}
