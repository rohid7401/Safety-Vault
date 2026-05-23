using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace PasswordManager.App.Services
{
    /// <summary>
    /// Talks to keys.openpgp.org via the Hagrid Verifying Keyserver (VKS) API.
    /// Search is anonymous. Publishing returns a token + verification email
    /// that the key owner must confirm before the key becomes searchable.
    /// </summary>
    public class KeyServerService
    {
        private const string BaseUrl = "https://keys.openpgp.org";
        private readonly HttpClient _http;

        public KeyServerService(HttpClient http)
        {
            _http = http;
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("SecureVault/1.0");
        }

        /// <summary>
        /// Searches keys.openpgp.org by email and returns the armored public key if found.
        /// Returns null if no key is published for that email.
        /// </summary>
        public async Task<string?> SearchByEmailAsync(string email, CancellationToken ct = default)
        {
            var url = $"{BaseUrl}/vks/v1/by-email/{Uri.EscapeDataString(email)}";
            try
            {
                var response = await _http.GetAsync(url, ct);
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound) return null;
                response.EnsureSuccessStatusCode();
                return await response.Content.ReadAsStringAsync(ct);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException(
                    $"Could not reach keys.openpgp.org: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Uploads an armored public key and returns the verification result.
        /// The user typically still needs to confirm via email before the key
        /// becomes searchable by address on keys.openpgp.org.
        /// </summary>
        public async Task<UploadResult> UploadAsync(string armoredPublicKey, CancellationToken ct = default)
        {
            var payload = new { keytext = armoredPublicKey };
            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            try
            {
                var response = await _http.PostAsync($"{BaseUrl}/vks/v1/upload", content, ct);
                response.EnsureSuccessStatusCode();
                var body = await response.Content.ReadAsStringAsync(ct);

                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                var token = root.TryGetProperty("token", out var t) ? t.GetString() : null;
                var keyFingerprint = root.TryGetProperty("key_fpr", out var f) ? f.GetString() : null;

                var emails = new List<EmailStatus>();
                if (root.TryGetProperty("status", out var status))
                {
                    foreach (var prop in status.EnumerateObject())
                        emails.Add(new EmailStatus(prop.Name, prop.Value.GetString() ?? "unknown"));
                }

                return new UploadResult(token ?? "", keyFingerprint ?? "", emails);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException(
                    $"Could not reach keys.openpgp.org: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Requests verification emails for the given addresses after an upload.
        /// </summary>
        public async Task RequestVerifyAsync(string token, IEnumerable<string> emails, CancellationToken ct = default)
        {
            var payload = new { token, addresses = emails.ToArray() };
            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _http.PostAsync($"{BaseUrl}/vks/v1/request-verify", content, ct);
            response.EnsureSuccessStatusCode();
        }

        public record UploadResult(string Token, string KeyFingerprint, List<EmailStatus> EmailStatuses);
        public record EmailStatus(string Email, string Status);
    }
}
