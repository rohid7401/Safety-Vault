using System.Text;
using System.Text.Json;
using PasswordManager.Core.Exceptions;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    public class ImportExportService : IImportExportService
    {
        public string ExportToCsv(IReadOnlyList<ExportRow> rows, IReadOnlyList<ExportColumn> columns)
        {
            if (columns.Count == 0)
                throw new InvalidOperationException("At least one column must be selected.");

            var sb = new StringBuilder();
            sb.AppendLine(string.Join(",", columns.Select(c => EscapeCsvField(c.Header))));

            foreach (var row in rows)
            {
                sb.AppendLine(string.Join(",", columns.Select(c =>
                    EscapeCsvField(c.Field.HasValue ? row.ValueOf(c.Field.Value) : c.Constant))));
            }

            return sb.ToString();
        }

        public string ExportToBackupJson(VaultBackup backup) =>
            JsonSerializer.Serialize(backup, BackupJsonOptions);

        /// <summary>
        /// Camel-cased and indented so the file is legible if someone opens an unencrypted
        /// backup, and stable across versions so diffs stay readable.
        /// </summary>
        private static readonly JsonSerializerOptions BackupJsonOptions = new()
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        };

        /// <summary>
        /// Picks the parser from the content itself. The three shapes are unambiguous — our own
        /// backup announces itself, a Bitwarden export is JSON with an <c>items</c> array, and
        /// anything else is treated as CSV (whose column aliases already absorb the dialect
        /// differences between managers). Detecting removes the whole class of "imported with
        /// the wrong format selected" failures.
        /// </summary>
        public ImportResult Import(string content)
        {
            GuardNotPgp(content);

            var trimmed = content.TrimStart();
            if (trimmed.StartsWith('{'))
            {
                return LooksLikeNativeBackup(trimmed)
                    ? ImportFromBackupJson(content)
                    : ImportFromBitwardenJson(content);
            }

            return ImportFromCsv(content);
        }

        private static bool LooksLikeNativeBackup(string trimmed)
        {
            // Cheap sniff before committing to a full parse; the real validation happens in
            // ImportFromBackupJson, which rejects a wrong version or a missing services array.
            var head = trimmed.Length <= 512 ? trimmed : trimmed[..512];
            return head.Contains(VaultBackup.ApplicationName, StringComparison.OrdinalIgnoreCase)
                && head.Contains("version", StringComparison.OrdinalIgnoreCase);
        }

        public ImportResult ImportFromBackupJson(string jsonContent)
        {
            GuardNotPgp(jsonContent);

            VaultBackup? backup;
            try
            {
                backup = JsonSerializer.Deserialize<VaultBackup>(jsonContent, BackupJsonOptions);
            }
            catch (JsonException)
            {
                throw new ImportFormatException(ImportFormatError.InvalidJson);
            }

            if (backup is null || !string.Equals(backup.Application, VaultBackup.ApplicationName, StringComparison.OrdinalIgnoreCase))
                throw new ImportFormatException(ImportFormatError.UnrecognizedColumns);

            // A newer major version may carry fields this build would silently drop, which on a
            // "restore my vault" path is worse than refusing.
            if (backup.Version > VaultBackup.CurrentVersion)
                throw new ImportFormatException(ImportFormatError.UnsupportedVersion);

            var services = backup.Services
                .Where(s => s.Credentials.Any(c => c.Fields.Count > 0))
                .ToList();

            var skipped = backup.Services.Count - services.Count;

            if (services.Count == 0)
                throw new ImportFormatException(ImportFormatError.NoUsableEntries);

            if (services.Count > ImportLimits.MaxEntries)
                throw new ImportFormatException(ImportFormatError.TooManyEntries);

            var truncated = 0;
            foreach (var service in services)
            {
                if (service.Site.Length > FieldLimits.Site)
                {
                    service.Site = FieldLimits.Clamp(service.Site, FieldLimits.Site);
                    truncated++;
                }

                foreach (var cred in service.Credentials)
                {
                    foreach (var field in cred.Fields)
                    {
                        var cap = CapFor(field.Type);
                        if (field.Value.Length > cap)
                        {
                            field.Value = FieldLimits.Clamp(field.Value, cap);
                            truncated++;
                        }
                    }
                }
            }

            backup.Services = services;
            return new ImportResult { Backup = backup, SkippedRows = skipped, TruncatedValues = truncated };
        }

        private static int CapFor(CredentialFieldType type) => type switch
        {
            CredentialFieldType.Email => FieldLimits.Email,
            CredentialFieldType.Username => FieldLimits.Username,
            CredentialFieldType.Password => FieldLimits.Password,
            CredentialFieldType.Pin => FieldLimits.Pin,
            CredentialFieldType.Phone => FieldLimits.Phone,
            CredentialFieldType.TwoFactor => FieldLimits.TwoFactorSecret,
            _ => FieldLimits.Text,
        };

        public ImportResult ImportFromCsv(string csvContent)
        {
            GuardNotPgp(csvContent);

            var entries = new List<PortableEntry>();
            var lines = csvContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            if (lines.Length < 2)
                throw new ImportFormatException(ImportFormatError.NoUsableEntries);

            if (lines.Length - 1 > ImportLimits.MaxRows)
                throw new ImportFormatException(ImportFormatError.TooManyEntries);

            var headers = ParseCsvLine(lines[0]);
            var headerMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < headers.Count; i++)
                headerMap[headers[i].Trim()] = i;

            // Without this the parser accepts literally any text: it treats line 0 as a
            // header, matches no column, and turns every remaining line into a blank
            // entry — which is how a signed .asc once imported as ~5000 empty passwords.
            if (!HasRecognizableColumns(headerMap))
                throw new ImportFormatException(ImportFormatError.UnrecognizedColumns);

            var skipped = 0;
            var truncated = 0;

            for (var i = 1; i < lines.Length; i++)
            {
                var fields = ParseCsvLine(lines[i]);
                if (fields.Count == 0) { skipped++; continue; }

                var entry = new PortableEntry
                {
                    Site = GetField(fields, headerMap, "site", "name", "url", "web site", "login_uri", "title"),
                    CredentialLabel = GetField(fields, headerMap, "credential_label", "account name"),
                    Username = GetField(fields, headerMap, "username", "login_username", "user", "login name", "account"),
                    Email = GetField(fields, headerMap, "email", "e-mail"),
                    Password = GetField(fields, headerMap, "password", "login_password"),
                    TotpSecret = GetFieldOrNull(fields, headerMap, "totp_secret", "totp", "login_totp", "otpauth"),
                    Notes = GetField(fields, headerMap, "notes", "note", "comments"),
                };

                var tagsRaw = GetField(fields, headerMap, "tags", "folder", "group");
                if (!string.IsNullOrEmpty(tagsRaw))
                    entry.Tags = tagsRaw.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList();

                if (IsBlank(entry)) { skipped++; continue; }

                truncated += ClampToFieldLimits(entry);
                entries.Add(entry);

                if (entries.Count > ImportLimits.MaxEntries)
                    throw new ImportFormatException(ImportFormatError.TooManyEntries);
            }

            if (entries.Count == 0)
                throw new ImportFormatException(ImportFormatError.NoUsableEntries);

            return new ImportResult { Entries = entries, SkippedRows = skipped, TruncatedValues = truncated };
        }

        public ImportResult ImportFromBitwardenJson(string jsonContent)
        {
            GuardNotPgp(jsonContent);

            var entries = new List<PortableEntry>();
            var skipped = 0;
            var truncated = 0;

            using var doc = ParseJsonOrThrow(jsonContent);
            var root = doc.RootElement;

            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("items", out var items) ||
                items.ValueKind != JsonValueKind.Array)
                throw new ImportFormatException(ImportFormatError.UnrecognizedColumns);

            foreach (var item in items.EnumerateArray())
            {
                if (item.TryGetProperty("type", out var type) && type.GetInt32() != 1)
                    continue;

                var entry = new PortableEntry
                {
                    Site = GetJsonString(item, "name"),
                };

                if (item.TryGetProperty("login", out var login))
                {
                    entry.Username = GetJsonString(login, "username");
                    entry.Password = GetJsonString(login, "password");
                    entry.TotpSecret = GetJsonStringOrNull(login, "totp");

                    if (item.TryGetProperty("login", out var loginObj) &&
                        loginObj.TryGetProperty("uris", out var uris))
                    {
                        foreach (var uri in uris.EnumerateArray())
                        {
                            var uriStr = GetJsonString(uri, "uri");
                            if (!string.IsNullOrEmpty(uriStr))
                            {
                                entry.Site = uriStr;
                                break;
                            }
                        }
                    }
                }

                if (item.TryGetProperty("folderId", out var folderId) &&
                    folderId.ValueKind == JsonValueKind.String)
                {
                    entry.Tags.Add(folderId.GetString()!);
                }

                if (IsBlank(entry)) { skipped++; continue; }

                truncated += ClampToFieldLimits(entry);
                entries.Add(entry);

                if (entries.Count > ImportLimits.MaxEntries)
                    throw new ImportFormatException(ImportFormatError.TooManyEntries);
            }

            if (entries.Count == 0)
                throw new ImportFormatException(ImportFormatError.NoUsableEntries);

            return new ImportResult { Entries = entries, SkippedRows = skipped, TruncatedValues = truncated };
        }

        private static JsonDocument ParseJsonOrThrow(string json)
        {
            try
            {
                return JsonDocument.Parse(json);
            }
            catch (JsonException)
            {
                throw new ImportFormatException(ImportFormatError.InvalidJson);
            }
        }

        /// <summary>
        /// Columns we know how to read. At least one must be present, otherwise the file
        /// is not a password export and every row would import as an empty entry.
        /// </summary>
        private static readonly string[] KnownColumns =
        {
            "site", "name", "url", "web site", "login_uri", "title",
            "username", "login_username", "user", "login name", "account",
            "email", "e-mail", "password", "login_password",
            "totp_secret", "totp", "login_totp", "otpauth",
        };

        private static bool HasRecognizableColumns(Dictionary<string, int> headers) =>
            KnownColumns.Any(headers.ContainsKey);

        /// <summary>
        /// Rejects any PGP armor up front. Only <c>BEGIN PGP MESSAGE</c> used to be
        /// detected (as "encrypted"), so a *signed* file — same armor, different header —
        /// fell through to the plaintext path and was parsed as CSV.
        /// </summary>
        private static void GuardNotPgp(string content)
        {
            var head = content.Length <= 512 ? content : content[..512];
            if (head.Contains("-----BEGIN PGP", StringComparison.Ordinal))
                throw new ImportFormatException(ImportFormatError.PgpBlock);
        }

        /// <summary>An entry with no identity and no secret carries nothing worth storing.</summary>
        private static bool IsBlank(PortableEntry e) =>
            string.IsNullOrWhiteSpace(e.Site) &&
            string.IsNullOrWhiteSpace(e.Username) &&
            string.IsNullOrWhiteSpace(e.Email) &&
            string.IsNullOrWhiteSpace(e.Password);

        /// <summary>
        /// Caps every value at the same limit the UI enforces on typed input, and returns
        /// how many had to be cut. Imported data bypasses the fields' own <c>maxlength</c>,
        /// so this is the only place those limits get applied to it.
        /// </summary>
        private static int ClampToFieldLimits(PortableEntry e)
        {
            var cut = 0;

            if (e.Site.Length > FieldLimits.Site) { e.Site = FieldLimits.Clamp(e.Site, FieldLimits.Site); cut++; }
            if (e.CredentialLabel.Length > FieldLimits.Label) { e.CredentialLabel = FieldLimits.Clamp(e.CredentialLabel, FieldLimits.Label); cut++; }
            if (e.Notes.Length > FieldLimits.NoteContent) { e.Notes = FieldLimits.Clamp(e.Notes, FieldLimits.NoteContent); cut++; }
            if (e.Username.Length > FieldLimits.Username) { e.Username = FieldLimits.Clamp(e.Username, FieldLimits.Username); cut++; }
            if (e.Email.Length > FieldLimits.Email) { e.Email = FieldLimits.Clamp(e.Email, FieldLimits.Email); cut++; }
            if (e.Password.Length > FieldLimits.Password) { e.Password = FieldLimits.Clamp(e.Password, FieldLimits.Password); cut++; }

            if (e.TotpSecret is { Length: > FieldLimits.TwoFactorSecret })
            {
                e.TotpSecret = FieldLimits.Clamp(e.TotpSecret, FieldLimits.TwoFactorSecret);
                cut++;
            }

            if (e.Tags.Count > 0)
            {
                var trimmed = e.Tags
                    .Take(FieldLimits.TagsPerEntry)
                    .Select(t => FieldLimits.Clamp(t, FieldLimits.Tag))
                    .ToList();

                if (trimmed.Count != e.Tags.Count || !trimmed.SequenceEqual(e.Tags)) cut++;
                e.Tags = trimmed;
            }

            return cut;
        }

        private static string EscapeCsvField(string field)
        {
            field = NeutralizeCsvInjection(field);
            if (field.Contains(',') || field.Contains('"') || field.Contains('\n'))
                return $"\"{field.Replace("\"", "\"\"")}\"";
            return field;
        }

        /// <summary>
        /// Prevents CSV/formula injection. Spreadsheet apps (Excel, LibreOffice, Sheets)
        /// evaluate any cell whose value starts with = + - @ (or a leading tab / CR) as a
        /// formula, which can exfiltrate data or run commands. Prefixing with a single
        /// quote forces the value to be treated as text.
        /// </summary>
        private static string NeutralizeCsvInjection(string field)
        {
            if (string.IsNullOrEmpty(field)) return field;
            char first = field[0];
            if (first is '=' or '+' or '-' or '@' or '\t' or '\r')
                return "'" + field;
            return field;
        }

        private static List<string> ParseCsvLine(string line)
        {
            var fields = new List<string>();
            var current = new StringBuilder();
            var inQuotes = false;

            for (var i = 0; i < line.Length; i++)
            {
                var c = line[i];
                if (c == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (c == ',' && !inQuotes)
                {
                    fields.Add(current.ToString());
                    current.Clear();
                }
                else if (c != '\r')
                {
                    current.Append(c);
                }
            }

            fields.Add(current.ToString());
            return fields;
        }

        private static string GetField(List<string> fields, Dictionary<string, int> headers, params string[] names)
        {
            foreach (var name in names)
            {
                if (headers.TryGetValue(name, out var idx) && idx < fields.Count)
                    return fields[idx];
            }
            return string.Empty;
        }

        private static string? GetFieldOrNull(List<string> fields, Dictionary<string, int> headers, params string[] names)
        {
            var value = GetField(fields, headers, names);
            return string.IsNullOrEmpty(value) ? null : value;
        }

        private static string GetJsonString(JsonElement element, string property)
        {
            if (element.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String)
                return prop.GetString() ?? string.Empty;
            return string.Empty;
        }

        private static string? GetJsonStringOrNull(JsonElement element, string property)
        {
            if (element.TryGetProperty(property, out var prop) && prop.ValueKind == JsonValueKind.String)
                return prop.GetString();
            return null;
        }
    }
}
