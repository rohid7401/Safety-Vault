using System.Text;
using System.Text.Json;
using PasswordManager.Core.Interfaces;
using PasswordManager.Core.Models;

namespace PasswordManager.Infrastructure.Services
{
    public class ImportExportService : IImportExportService
    {
        public string ExportToCsv(IReadOnlyList<PortableEntry> entries)
        {
            var sb = new StringBuilder();
            sb.AppendLine("site,username,email,password,totp_secret,tags");

            foreach (var entry in entries)
            {
                sb.AppendLine(string.Join(",",
                    EscapeCsvField(entry.Site),
                    EscapeCsvField(entry.Username),
                    EscapeCsvField(entry.Email),
                    EscapeCsvField(entry.Password),
                    EscapeCsvField(entry.TotpSecret ?? ""),
                    EscapeCsvField(string.Join(";", entry.Tags))));
            }

            return sb.ToString();
        }

        public List<PortableEntry> ImportFromCsv(string csvContent)
        {
            var entries = new List<PortableEntry>();
            var lines = csvContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            if (lines.Length < 2) return entries;

            var headers = ParseCsvLine(lines[0]);
            var headerMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < headers.Count; i++)
                headerMap[headers[i].Trim()] = i;

            for (var i = 1; i < lines.Length; i++)
            {
                var fields = ParseCsvLine(lines[i]);
                if (fields.Count == 0) continue;

                var entry = new PortableEntry
                {
                    Site = GetField(fields, headerMap, "site", "name", "url"),
                    Username = GetField(fields, headerMap, "username", "login_username", "user"),
                    Email = GetField(fields, headerMap, "email"),
                    Password = GetField(fields, headerMap, "password", "login_password"),
                    TotpSecret = GetFieldOrNull(fields, headerMap, "totp_secret", "totp", "login_totp"),
                };

                var tagsRaw = GetField(fields, headerMap, "tags");
                if (!string.IsNullOrEmpty(tagsRaw))
                    entry.Tags = tagsRaw.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList();

                entries.Add(entry);
            }

            return entries;
        }

        public List<PortableEntry> ImportFromBitwardenJson(string jsonContent)
        {
            var entries = new List<PortableEntry>();

            using var doc = JsonDocument.Parse(jsonContent);
            var root = doc.RootElement;

            if (!root.TryGetProperty("items", out var items))
                return entries;

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
                    folderId.ValueKind != JsonValueKind.Null)
                {
                    entry.Tags.Add(folderId.GetString()!);
                }

                entries.Add(entry);
            }

            return entries;
        }

        private static string EscapeCsvField(string field)
        {
            if (field.Contains(',') || field.Contains('"') || field.Contains('\n'))
                return $"\"{field.Replace("\"", "\"\"")}\"";
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
