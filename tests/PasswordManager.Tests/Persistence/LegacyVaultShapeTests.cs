using System.Text.Json;
using PasswordManager.Core.Models;
using Xunit;

namespace PasswordManager.Tests.Persistence
{
    /// <summary>
    /// Guards the upgrade path for vaults that already exist on testers' devices. Every field
    /// added to the models has to be readable-by-omission: the vault is plain
    /// <c>System.Text.Json</c>, so a document written by an older build simply lacks the new
    /// properties, and loading it must yield the same entries rather than an error or a wipe.
    /// </summary>
    public class LegacyVaultShapeTests
    {
        /// <summary>
        /// A vault exactly as the shipped build writes it: enum types as bare integers, no
        /// <c>LastChanged</c> on the field, no <c>Web</c> field anywhere.
        /// </summary>
        private const string VaultWrittenByShippedBuild = """
            {
              "Version": 5,
              "Algorithm": "AES-GCM-256",
              "Entries": [
                {
                  "$type": "service",
                  "Site": "github.com",
                  "Grouped": false,
                  "Credentials": [
                    {
                      "Id": "6f9619ff-8b86-d011-b42d-00cf4fc964ff",
                      "Label": "Personal",
                      "Fields": [
                        { "Type": 0, "IsSecret": false, "PlainValue": "yo@example.com" },
                        { "Type": 6, "IsSecret": false, "PlainValue": "cuenta vieja" },
                        { "Type": 2, "IsSecret": true, "PlainValue": "" }
                      ],
                      "CreationTime": "2025-03-04T10:00:00Z",
                      "LastUpdateTime": "2025-03-04T10:00:00Z"
                    }
                  ],
                  "Id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                  "Tags": ["trabajo"],
                  "CreationTime": "2025-03-04T10:00:00Z",
                  "LastUpdateTime": "2025-03-04T10:00:00Z",
                  "IsDeleted": false
                }
              ]
            }
            """;

        [Fact]
        public void OldVault_StillLoads_WithEveryValuePreserved()
        {
            var vault = JsonSerializer.Deserialize<VaultData>(VaultWrittenByShippedBuild)!;

            var entry = Assert.IsType<ServiceEntry>(Assert.Single(vault.Entries));
            Assert.Equal("github.com", entry.Site);
            Assert.Equal(new[] { "trabajo" }, entry.Tags);
            Assert.Equal(new DateTime(2025, 3, 4, 10, 0, 0, DateTimeKind.Utc), entry.CreationTime.ToUniversalTime());

            var cred = Assert.Single(entry.Credentials);
            Assert.Equal("Personal", cred.Label);
            Assert.Equal(3, cred.Fields.Count);
        }

        /// <summary>
        /// The reason <c>Web</c> had to be appended to the enum rather than slotted in next to the
        /// other identity types: a stored 6 means Text, and it must still mean Text afterwards.
        /// </summary>
        [Fact]
        public void OldVault_StoredFieldTypes_DoNotShift()
        {
            var vault = JsonSerializer.Deserialize<VaultData>(VaultWrittenByShippedBuild)!;
            var fields = ((ServiceEntry)vault.Entries[0]).Credentials[0].Fields;

            Assert.Equal(CredentialFieldType.Email, fields[0].Type);
            Assert.Equal(CredentialFieldType.Text, fields[1].Type);
            Assert.Equal("cuenta vieja", fields[1].PlainValue);
            Assert.Equal(CredentialFieldType.Password, fields[2].Type);
        }

        /// <summary>
        /// An untouched old password has no recorded change date, and the UI must be able to tell
        /// that apart from "changed today" so it can stay silent instead of reporting a fiction.
        /// </summary>
        [Fact]
        public void OldVault_PasswordWithoutHistory_HasUnknownChangeDate()
        {
            var vault = JsonSerializer.Deserialize<VaultData>(VaultWrittenByShippedBuild)!;
            var password = ((ServiceEntry)vault.Entries[0]).Credentials[0].Fields[2];

            Assert.Null(password.LastChanged);
        }
    }
}
