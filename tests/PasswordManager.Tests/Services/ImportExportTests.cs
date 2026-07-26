using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Models;
using PasswordManager.Infrastructure.Services;
using Xunit;

namespace PasswordManager.Tests.Services
{
    public class ImportExportTests
    {
        private readonly ImportExportService _service = new();

        private static List<ExportRow> Rows(params ExportRow[] rows) => rows.ToList();

        private static IReadOnlyList<ExportColumn> AllOf(ExportTarget target) =>
            ExportPresets.For(target);

        [Fact]
        public void ExportToCsv_Generic_WritesPresetHeadersAndValues()
        {
            var rows = Rows(new ExportRow
            {
                Site = "example.com",
                CredentialLabel = "Personal",
                Username = "user1",
                Email = "user@example.com",
                Password = "Secret123!",
                Web = "https://example.com/login",
                Tags = "work;email",
            });

            var csv = _service.ExportToCsv(rows, AllOf(ExportTarget.GenericCsv));

            Assert.Contains("site,credential_label,username,email,password,pin,phone,url,totp_secret,notes,tags", csv);
            Assert.Contains("example.com", csv);
            Assert.Contains("Personal", csv);
            Assert.Contains("Secret123!", csv);
            Assert.Contains("https://example.com/login", csv);
            Assert.Contains("work;email", csv);
        }

        [Fact]
        public void ImportCsv_ChromeExport_KeepsNameAsSiteAndUrlAsWeb()
        {
            var csv = "name,url,username,password,note\n" +
                      "Universidad,https://plataforma.uni.ac.cr,alum@uni.ac.cr,Passw0rd!,\n";

            var entry = Assert.Single(_service.Import(csv).Entries!);

            Assert.Equal("Universidad", entry.Site);
            Assert.Equal("https://plataforma.uni.ac.cr", entry.Web);
        }

        [Fact]
        public void ImportCsv_UrlOnlyAndNoTitle_FallsBackToUrlAsSite()
        {
            var csv = "url,username,password\nhttps://matricula.uni.ac.cr,alum@uni.ac.cr,Passw0rd!\n";

            var entry = Assert.Single(_service.Import(csv).Entries!);

            Assert.Equal("https://matricula.uni.ac.cr", entry.Site);
        }

        [Fact]
        public void ExportToCsv_Bitwarden_FillsLoginUriFromWebField()
        {
            var rows = Rows(new ExportRow { Site = "Universidad", Web = "https://pagos.uni.ac.cr", Password = "p" });

            var csv = _service.ExportToCsv(rows, AllOf(ExportTarget.BitwardenCsv));

            Assert.Contains("https://pagos.uni.ac.cr", csv);
        }

        [Fact]
        public void ExportToCsv_FieldWithComma_EscapesCorrectly()
        {
            var rows = Rows(new ExportRow { Site = "site,with,commas", Password = "pass" });

            var csv = _service.ExportToCsv(rows, AllOf(ExportTarget.GenericCsv));

            Assert.Contains("\"site,with,commas\"", csv);
        }

        [Fact]
        public void ExportToCsv_DeselectedField_IsOmittedEntirely()
        {
            var rows = Rows(new ExportRow { Site = "a.com", Password = "p", TotpSecret = "SECRET2FA" });

            // Dropping a field must remove its column, not just blank the cell — the point is
            // that the value never leaves the device.
            var columns = ExportPresets.For(ExportTarget.GenericCsv)
                .Where(c => c.Field != ExportField.TotpSecret)
                .ToList();

            var csv = _service.ExportToCsv(rows, columns);

            Assert.DoesNotContain("totp_secret", csv);
            Assert.DoesNotContain("SECRET2FA", csv);
            Assert.Contains("a.com", csv);
        }

        [Fact]
        public void ExportToCsv_Bitwarden_UsesItsOwnHeadersAndConstants()
        {
            var rows = Rows(new ExportRow { Site = "a.com", Email = "me@a.com", Password = "p" });

            var csv = _service.ExportToCsv(rows, AllOf(ExportTarget.BitwardenCsv));
            var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.TrimEnd('\r')).ToList();

            Assert.Equal("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp", lines[0]);
            // type=login and reprompt=0 are structural constants, written on every row.
            Assert.Contains("login", lines[1]);
            Assert.Contains(",0,", lines[1]);
        }

        [Fact]
        public void ExportToCsv_SingleLoginColumn_FallsBackToEmail()
        {
            // Most credentials here sign in with an email and carry no username; a
            // Username-only mapping would export an empty column for all of them.
            var rows = Rows(new ExportRow { Site = "a.com", Email = "me@a.com", Password = "p" });

            var csv = _service.ExportToCsv(rows, AllOf(ExportTarget.ChromeCsv));

            Assert.Contains("me@a.com", csv);
        }

        [Fact]
        public void ExportToCsv_NoColumns_Throws()
        {
            Assert.Throws<InvalidOperationException>(
                () => _service.ExportToCsv(Rows(new ExportRow()), new List<ExportColumn>()));
        }

        [Fact]
        public void ImportFromCsv_ValidCsv_ParsesCorrectly()
        {
            var csv = "site,username,email,password,totp_secret,tags\n" +
                       "example.com,user1,user@test.com,Pass123!,JBSWY3DPEHPK3PXP,work;personal\n";

            var entries = _service.ImportFromCsv(csv).Entries;

            Assert.Single(entries);
            Assert.Equal("example.com", entries[0].Site);
            Assert.Equal("user1", entries[0].Username);
            Assert.Equal("user@test.com", entries[0].Email);
            Assert.Equal("Pass123!", entries[0].Password);
            Assert.Equal("JBSWY3DPEHPK3PXP", entries[0].TotpSecret);
            Assert.Equal(2, entries[0].Tags.Count);
        }

        [Fact]
        public void ImportFromCsv_EmptyContent_Throws()
        {
            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromCsv(""));
            Assert.Equal(ImportFormatError.NoUsableEntries, ex.Reason);
        }

        [Fact]
        public void ImportFromCsv_HeaderOnly_Throws()
        {
            var ex = Assert.Throws<ImportFormatException>(
                () => _service.ImportFromCsv("site,username,password\n"));
            Assert.Equal(ImportFormatError.NoUsableEntries, ex.Reason);
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

            var rows = Rows(new ExportRow
            {
                Site = original[0].Site,
                CredentialLabel = "Work",
                Username = original[0].Username,
                Email = original[0].Email,
                Password = original[0].Password,
                TotpSecret = original[0].TotpSecret!,
                Tags = "servers",
            });

            var csv = _service.ExportToCsv(rows, AllOf(ExportTarget.GenericCsv));
            var imported = _service.ImportFromCsv(csv).Entries;

            Assert.Single(imported);
            Assert.Equal(original[0].Site, imported[0].Site);
            Assert.Equal("Work", imported[0].CredentialLabel);
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

            var entries = _service.ImportFromBitwardenJson(json).Entries;

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

            var entries = _service.ImportFromBitwardenJson(json).Entries;

            Assert.Single(entries);
            Assert.Equal("user", entries[0].Username);
        }

        [Fact]
        public void ImportFromBitwardenJson_EmptyItems_Throws()
        {
            var json = """{ "items": [] }""";
            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromBitwardenJson(json));
            Assert.Equal(ImportFormatError.NoUsableEntries, ex.Reason);
        }

        [Fact]
        public void ImportFromBitwardenJson_NoItemsProperty_Throws()
        {
            var json = """{ "folders": [] }""";
            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromBitwardenJson(json));
            Assert.Equal(ImportFormatError.UnrecognizedColumns, ex.Reason);
        }

        [Fact]
        public void ImportFromCsv_AlternateHeaders_MapsCorrectly()
        {
            var csv = "name,login_username,login_password\n" +
                       "MySite,myuser,mypass\n";

            var entries = _service.ImportFromCsv(csv).Entries;

            Assert.Single(entries);
            Assert.Equal("MySite", entries[0].Site);
            Assert.Equal("myuser", entries[0].Username);
            Assert.Equal("mypass", entries[0].Password);
        }

        [Fact]
        public void ExportToCsv_WithTotpSecret_IncludesInOutput()
        {
            var rows = Rows(new ExportRow
            {
                Site = "2fa-site.com",
                Username = "user",
                Password = "pass",
                TotpSecret = "JBSWY3DPEHPK3PXP",
            });

            var csv = _service.ExportToCsv(rows, AllOf(ExportTarget.GenericCsv));

            Assert.Contains("JBSWY3DPEHPK3PXP", csv);
        }

        [Fact]
        public void ImportFromCsv_MultipleEntries_ParsesAll()
        {
            var csv = "site,username,password\n" +
                       "site1.com,user1,pass1\n" +
                       "site2.com,user2,pass2\n" +
                       "site3.com,user3,pass3\n";

            var result = _service.ImportFromCsv(csv);

            Assert.Equal(3, result.Entries.Count);
        }

        // ── Format guards ──────────────────────────────────────────────────
        // Regression: a PGP-*signed* file (same armor as an encrypted one, different
        // header) used to slip past the "is it encrypted?" check, get read as plain
        // text, and import one blank entry per line of the base64 signature block.

        [Theory]
        [InlineData("-----BEGIN PGP SIGNED MESSAGE-----")]
        [InlineData("-----BEGIN PGP MESSAGE-----")]
        [InlineData("-----BEGIN PGP PUBLIC KEY BLOCK-----")]
        [InlineData("-----BEGIN PGP SIGNATURE-----")]
        public void ImportFromCsv_PgpArmor_IsRejected(string header)
        {
            var content = header + "\nHash: SHA256\n\nsite,username,password\na,b,c\n";

            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromCsv(content));
            Assert.Equal(ImportFormatError.PgpBlock, ex.Reason);
        }

        [Fact]
        public void ImportFromCsv_SignatureBlock_DoesNotProduceBlankEntries()
        {
            // The exact shape that produced ~5000 empty passwords: many lines of base64
            // with no recognizable header row.
            var body = string.Join("\n", Enumerable.Repeat("iQIzBAEBCgAdFiEE0mFQ8pKZ7yYQ3H3vX", 4987));

            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromCsv(body));
            Assert.Equal(ImportFormatError.UnrecognizedColumns, ex.Reason);
        }

        [Fact]
        public void ImportFromCsv_UnknownHeaders_IsRejected()
        {
            var csv = "alpha,beta,gamma\n1,2,3\n";

            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromCsv(csv));
            Assert.Equal(ImportFormatError.UnrecognizedColumns, ex.Reason);
        }

        [Fact]
        public void ImportFromCsv_BlankRows_AreSkippedNotImported()
        {
            var csv = "site,username,password\n" +
                       "real.com,user,pass\n" +
                       ",,\n" +
                       ",,\n";

            var result = _service.ImportFromCsv(csv);

            Assert.Single(result.Entries);
            Assert.Equal(2, result.SkippedRows);
        }

        [Fact]
        public void ImportFromCsv_OverlongValues_AreTruncatedAndCounted()
        {
            var csv = "site,username,password\n" +
                       $"a.com,user,{new string('x', FieldLimits.Password + 500)}\n";

            var result = _service.ImportFromCsv(csv);

            Assert.Equal(FieldLimits.Password, result.Entries[0].Password.Length);
            Assert.Equal(1, result.TruncatedValues);
        }

        [Fact]
        public void ImportFromCsv_TooManyRows_IsRejected()
        {
            var rows = string.Join("\n",
                Enumerable.Range(0, ImportLimits.MaxRows + 2).Select(i => $"s{i}.com,u{i},p{i}"));
            var csv = "site,username,password\n" + rows + "\n";

            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromCsv(csv));
            Assert.Equal(ImportFormatError.TooManyEntries, ex.Reason);
        }

        [Fact]
        public void ImportFromBitwardenJson_Garbage_IsRejected()
        {
            var ex = Assert.Throws<ImportFormatException>(
                () => _service.ImportFromBitwardenJson("not json at all"));
            Assert.Equal(ImportFormatError.InvalidJson, ex.Reason);
        }

        // ─── Native backup ─────────────────────────────────────────────────

        private static VaultBackup SampleBackup() => new()
        {
            Services =
            {
                new BackupServiceEntry
                {
                    Site = "bank.com",
                    Tags = { "finance" },
                    Grouped = true,
                    Credentials =
                    {
                        new BackupCredential
                        {
                            Label = "Personal",
                            Fields =
                            {
                                new BackupField { Type = CredentialFieldType.Email, Value = "me@bank.com" },
                                new BackupField { Type = CredentialFieldType.Password, IsSecret = true, Value = "P@ss1" },
                                new BackupField { Type = CredentialFieldType.Pin, IsSecret = true, Value = "4821" },
                            },
                        },
                        new BackupCredential
                        {
                            Label = "Business",
                            Fields =
                            {
                                new BackupField { Type = CredentialFieldType.Username, Value = "acme" },
                                new BackupField { Type = CredentialFieldType.Password, IsSecret = true, Value = "P@ss2" },
                            },
                        },
                    },
                },
            },
        };

        [Fact]
        public void BackupJson_Roundtrips_WithFullDetail()
        {
            var json = _service.ExportToBackupJson(SampleBackup());

            var backup = _service.ImportFromBackupJson(json).Backup!;

            var service = Assert.Single(backup.Services);
            Assert.Equal("bank.com", service.Site);
            Assert.Equal(new[] { "finance" }, service.Tags);
            Assert.Equal(2, service.Credentials.Count);

            // The two things the flat CSV shape cannot express: which account a credential is,
            // and field types beyond username/password/2FA.
            Assert.Equal(new[] { "Personal", "Business" }, service.Credentials.Select(c => c.Label));
            Assert.Contains(service.Credentials[0].Fields, f => f.Type == CredentialFieldType.Pin && f.Value == "4821");
        }

        [Fact]
        public void Import_DetectsNativeBackup()
        {
            var json = _service.ExportToBackupJson(SampleBackup());

            var result = _service.Import(json);

            Assert.True(result.IsNativeBackup);
            Assert.Equal(1, result.EntryCount);
        }

        [Fact]
        public void Import_DetectsBitwardenJson()
        {
            var json = """{ "items": [ { "type": 1, "name": "x", "login": { "username": "u", "password": "p" } } ] }""";

            var result = _service.Import(json);

            Assert.False(result.IsNativeBackup);
            Assert.Single(result.Entries);
        }

        [Fact]
        public void Import_DetectsCsv()
        {
            var result = _service.Import("site,username,password\na.com,u,p\n");

            Assert.False(result.IsNativeBackup);
            Assert.Single(result.Entries);
        }

        [Fact]
        public void Import_PgpArmor_IsRejectedBeforeAnyParsing()
        {
            var ex = Assert.Throws<ImportFormatException>(
                () => _service.Import("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nsite\n"));
            Assert.Equal(ImportFormatError.PgpBlock, ex.Reason);
        }

        [Fact]
        public void ImportFromBackupJson_NewerVersion_IsRejected()
        {
            var backup = SampleBackup();
            backup.Version = VaultBackup.CurrentVersion + 1;
            var json = _service.ExportToBackupJson(backup);

            // Better to refuse than to restore a vault while silently dropping fields this
            // build does not understand.
            var ex = Assert.Throws<ImportFormatException>(() => _service.ImportFromBackupJson(json));
            Assert.Equal(ImportFormatError.UnsupportedVersion, ex.Reason);
        }

        [Fact]
        public void ImportFromBackupJson_ForeignJson_IsRejected()
        {
            var ex = Assert.Throws<ImportFormatException>(
                () => _service.ImportFromBackupJson("""{ "application": "SomethingElse", "version": 1 }"""));
            Assert.Equal(ImportFormatError.UnrecognizedColumns, ex.Reason);
        }

        [Fact]
        public void ImportFromBackupJson_OverlongValues_AreTruncated()
        {
            var backup = SampleBackup();
            backup.Services[0].Credentials[0].Fields[1].Value = new string('x', FieldLimits.Password + 200);

            var result = _service.ImportFromBackupJson(_service.ExportToBackupJson(backup));

            Assert.Equal(FieldLimits.Password, result.Backup!.Services[0].Credentials[0].Fields[1].Value.Length);
            Assert.Equal(1, result.TruncatedValues);
        }

        // ─── Broader CSV dialects ──────────────────────────────────────────

        [Theory]
        // Chrome / Edge / Google
        [InlineData("name,url,username,password,note\nGitHub,https://github.com,octocat,hunter2,\n", "octocat", "hunter2")]
        // KeePass / KeePassXC
        [InlineData("Account,Login Name,Password,Web Site,Comments\nGitHub,octocat,hunter2,https://github.com,\n", "octocat", "hunter2")]
        // Bitwarden's own CSV export
        [InlineData("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,GitHub,,,0,https://github.com,octocat,hunter2,\n", "octocat", "hunter2")]
        public void ImportFromCsv_ForeignDialects_AreUnderstood(string csv, string expectedUser, string expectedPassword)
        {
            var entries = _service.ImportFromCsv(csv).Entries;

            var entry = Assert.Single(entries);
            Assert.Equal(expectedUser, entry.Username);
            Assert.Equal(expectedPassword, entry.Password);
        }

        [Fact]
        public void ImportFromCsv_NotesColumn_IsKept()
        {
            var csv = "name,username,password,note\na.com,u,p,recovery code 1234\n";

            var entry = Assert.Single(_service.ImportFromCsv(csv).Entries);

            Assert.Equal("recovery code 1234", entry.Notes);
        }
    }
}
