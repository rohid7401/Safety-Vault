using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class ImportExportTests
    {
        private readonly ImportExportService _service = new();

        [Fact]
        public void ExportToCsv_SingleEntry_ProducesValidCsv()
        {
            var entries = new List<PortableEntry>
            {
                new()
                {
                    Site = "example.com",
                    Username = "user1",
                    Email = "user@example.com",
                    Password = "Secret123!",
                    Tags = new List<string> { "work", "email" }
                }
            };

            var csv = _service.ExportToCsv(entries);

            Assert.Contains("site,username,email,password,totp_secret,tags", csv);
            Assert.Contains("example.com", csv);
            Assert.Contains("user1", csv);
            Assert.Contains("Secret123!", csv);
            Assert.Contains("work;email", csv);
        }

        [Fact]
        public void ExportToCsv_FieldWithComma_EscapesCorrectly()
        {
            var entries = new List<PortableEntry>
            {
                new() { Site = "site,with,commas", Password = "pass" }
            };

            var csv = _service.ExportToCsv(entries);

            Assert.Contains("\"site,with,commas\"", csv);
        }

        [Fact]
        public void ImportFromCsv_ValidCsv_ParsesCorrectly()
        {
            var csv = "site,username,email,password,totp_secret,tags\n" +
                       "example.com,user1,user@test.com,Pass123!,JBSWY3DPEHPK3PXP,work;personal\n";

            var entries = _service.ImportFromCsv(csv);

            Assert.Single(entries);
            Assert.Equal("example.com", entries[0].Site);
            Assert.Equal("user1", entries[0].Username);
            Assert.Equal("user@test.com", entries[0].Email);
            Assert.Equal("Pass123!", entries[0].Password);
            Assert.Equal("JBSWY3DPEHPK3PXP", entries[0].TotpSecret);
            Assert.Equal(2, entries[0].Tags.Count);
        }

        [Fact]
        public void ImportFromCsv_EmptyContent_ReturnsEmptyList()
        {
            var entries = _service.ImportFromCsv("");
            Assert.Empty(entries);
        }

        [Fact]
        public void ImportFromCsv_HeaderOnly_ReturnsEmptyList()
        {
            var entries = _service.ImportFromCsv("site,username,password\n");
            Assert.Empty(entries);
        }

        [Fact]
        public void ExportThenImport_Roundtrip_PreservesData()
        {
            var original = new List<PortableEntry>
            {
                new()
                {
                    Site = "test.com",
                    Username = "admin",
                    Email = "admin@test.com",
                    Password = "MyP@ss!123",
                    TotpSecret = "JBSWY3DPEHPK3PXP",
                    Tags = new List<string> { "servers" }
                }
            };

            var csv = _service.ExportToCsv(original);
            var imported = _service.ImportFromCsv(csv);

            Assert.Single(imported);
            Assert.Equal(original[0].Site, imported[0].Site);
            Assert.Equal(original[0].Username, imported[0].Username);
            Assert.Equal(original[0].Email, imported[0].Email);
            Assert.Equal(original[0].Password, imported[0].Password);
            Assert.Equal(original[0].TotpSecret, imported[0].TotpSecret);
            Assert.Equal(original[0].Tags, imported[0].Tags);
        }

        [Fact]
        public void ImportFromBitwardenJson_ValidExport_ParsesLoginEntries()
        {
            var json = """
            {
              "items": [
                {
                  "type": 1,
                  "name": "My Login",
                  "login": {
                    "username": "user@example.com",
                    "password": "SuperSecret!",
                    "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [
                      { "uri": "https://example.com" }
                    ]
                  }
                }
              ]
            }
            """;

            var entries = _service.ImportFromBitwardenJson(json);

            Assert.Single(entries);
            Assert.Equal("https://example.com", entries[0].Site);
            Assert.Equal("user@example.com", entries[0].Username);
            Assert.Equal("SuperSecret!", entries[0].Password);
            Assert.Equal("JBSWY3DPEHPK3PXP", entries[0].TotpSecret);
        }

        [Fact]
        public void ImportFromBitwardenJson_NonLoginType_IsSkipped()
        {
            var json = """
            {
              "items": [
                {
                  "type": 2,
                  "name": "Secure Note",
                  "notes": "Some note content"
                },
                {
                  "type": 1,
                  "name": "Login Entry",
                  "login": {
                    "username": "user",
                    "password": "pass"
                  }
                }
              ]
            }
            """;

            var entries = _service.ImportFromBitwardenJson(json);

            Assert.Single(entries);
            Assert.Equal("user", entries[0].Username);
        }

        [Fact]
        public void ImportFromBitwardenJson_EmptyItems_ReturnsEmptyList()
        {
            var json = """{ "items": [] }""";
            var entries = _service.ImportFromBitwardenJson(json);
            Assert.Empty(entries);
        }

        [Fact]
        public void ImportFromBitwardenJson_NoItemsProperty_ReturnsEmptyList()
        {
            var json = """{ "folders": [] }""";
            var entries = _service.ImportFromBitwardenJson(json);
            Assert.Empty(entries);
        }

        [Fact]
        public void ImportFromCsv_AlternateHeaders_MapsCorrectly()
        {
            var csv = "name,login_username,login_password\n" +
                       "MySite,myuser,mypass\n";

            var entries = _service.ImportFromCsv(csv);

            Assert.Single(entries);
            Assert.Equal("MySite", entries[0].Site);
            Assert.Equal("myuser", entries[0].Username);
            Assert.Equal("mypass", entries[0].Password);
        }

        [Fact]
        public void ExportToCsv_WithTotpSecret_IncludesInOutput()
        {
            var entries = new List<PortableEntry>
            {
                new()
                {
                    Site = "2fa-site.com",
                    Username = "user",
                    Password = "pass",
                    TotpSecret = "JBSWY3DPEHPK3PXP"
                }
            };

            var csv = _service.ExportToCsv(entries);

            Assert.Contains("JBSWY3DPEHPK3PXP", csv);
        }

        [Fact]
        public void ImportFromCsv_MultipleEntries_ParsesAll()
        {
            var csv = "site,username,password\n" +
                       "site1.com,user1,pass1\n" +
                       "site2.com,user2,pass2\n" +
                       "site3.com,user3,pass3\n";

            var entries = _service.ImportFromCsv(csv);

            Assert.Equal(3, entries.Count);
        }
    }
}
