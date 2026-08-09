using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using PasswordManager.Core.Exceptions;

namespace PasswordManager.UI.Services
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
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("SafetyVault/1.0");
        }

        /// <summary>
        /// The directories searched, in the order their answers are preferred.
        ///
        /// <para><see cref="KeyServerSource.VerifiesOwnership"/> is the distinction that matters
        /// and the reason the order is fixed rather than a race. A verifying server only publishes
        /// an address once its owner has confirmed it by e-mail; the older SKS-style ones accept
        /// whatever anyone uploads, including a key claiming an address the uploader does not own.
        /// They are still worth asking — they hold keys that were never re-published to the newer
        /// servers — but an answer that comes only from them is a weaker claim, and the caller is
        /// told so.</para>
        /// </summary>
        public static readonly IReadOnlyList<KeyServerSource> Sources = new[]
        {
            new KeyServerSource("keys.openpgp.org",
                "https://keys.openpgp.org/vks/v1/by-email/{0}", VerifiesOwnership: true),
            new KeyServerSource("keys.mailvelope.com",
                "https://keys.mailvelope.com/vks/v1/by-email/{0}", VerifiesOwnership: true),
            new KeyServerSource("keyserver.ubuntu.com",
                "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search={0}", VerifiesOwnership: false),
        };

        /// <summary>
        /// One server is allowed to be slow without holding up the rest. The servers replicate to
        /// each other, but that can lag by hours — asking several at once is what makes a key
        /// published minutes ago findable now.
        /// </summary>
        private static readonly TimeSpan PerServerTimeout = TimeSpan.FromSeconds(8);

        /// <summary>
        /// Asks every directory at once and returns whatever each one had, in <see cref="Sources"/>
        /// order rather than by who replied first — so the same search gives the same answer twice
        /// running, instead of depending on which server happened to be quick.
        /// </summary>
        public async Task<KeySearchOutcome> SearchAllAsync(string email, CancellationToken ct = default)
        {
            var attempts = Sources.Select(source => FetchAsync(source, email, ct)).ToArray();
            var results = await Task.WhenAll(attempts);

            var hits = results.Where(r => r.Armored is not null)
                .Select(r => new KeyServerHit(r.Source, r.Armored!))
                .ToList();
            var unreachable = results.Where(r => r.Failed).Select(r => r.Source.Name).ToList();

            // Every server was unreachable and none had anything: that is a connectivity problem,
            // not an answer of "no key exists". Saying "not found" would be a lie.
            if (hits.Count == 0 && unreachable.Count == Sources.Count)
                throw new LocalizedInvalidOperationException(AppErrorCode.KeyServerUnreachable);

            return new KeySearchOutcome(hits, unreachable);
        }

        private async Task<(KeyServerSource Source, string? Armored, bool Failed)> FetchAsync(
            KeyServerSource source, string email, CancellationToken ct)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(PerServerTimeout);

            try
            {
                var url = string.Format(source.SearchUrlTemplate, Uri.EscapeDataString(email));
                var response = await _http.GetAsync(url, timeout.Token);

                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                    return (source, null, false);   // answered, and had nothing
                if (!response.IsSuccessStatusCode)
                    return (source, null, true);

                var body = await response.Content.ReadAsStringAsync(timeout.Token);

                // HKP servers answer 200 with an HTML "no results" page rather than a 404, so the
                // body has to be checked: without this, a search would "find" a web page.
                return body.Contains("BEGIN PGP PUBLIC KEY BLOCK", StringComparison.Ordinal)
                    ? (source, body, false)
                    : (source, null, false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return (source, null, true);   // this server timed out; the others still count
            }
            catch (HttpRequestException)
            {
                return (source, null, true);
            }
        }

        /// <summary>
        /// Searches only keys.openpgp.org. Kept for the publish flow, which has to check that
        /// specific server — the one the key was uploaded to.
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
            catch (HttpRequestException)
            {
                // The technical detail stays in the log; the code is what the user sees,
                // translated, without the transport error's English text.
                throw new LocalizedInvalidOperationException(AppErrorCode.KeyServerUnreachable);
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
                // The inner exception keeps the technical detail for the log; the code is what
                // the user sees, translated, without the transport error's English text.
                throw new LocalizedInvalidOperationException(AppErrorCode.KeyServerUnreachable);
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

    /// <summary>A public-key directory, and whether it checks that an address belongs to whoever
    /// published a key under it.</summary>
    public sealed record KeyServerSource(string Name, string SearchUrlTemplate, bool VerifiesOwnership);

    /// <summary>An armored key as one directory returned it.</summary>
    public sealed record KeyServerHit(KeyServerSource Source, string Armored);

    /// <summary>
    /// What the directories collectively said. Deliberately keeps every answer instead of
    /// collapsing to one: which servers had the key, and whether they agreed, is the part a user
    /// needs in order to judge what they are about to trust.
    /// </summary>
    public sealed record KeySearchOutcome(
        IReadOnlyList<KeyServerHit> Hits,
        IReadOnlyList<string> Unreachable)
    {
        public bool Found => Hits.Count > 0;

        /// <summary>The preferred answer: the first hit in <see cref="KeyServerService.Sources"/>
        /// order, which puts the verifying directories ahead of the open ones.</summary>
        public KeyServerHit? Best => Hits.Count > 0 ? Hits[0] : null;

        public IReadOnlyList<string> FoundOn => Hits.Select(h => h.Source.Name).ToList();

        /// <summary>
        /// True when the key turned up only on directories that never checked the address. The key
        /// may be perfectly genuine — but nothing about where it was found says so, and the user
        /// should lean harder on the fingerprint before trusting it.
        /// </summary>
        public bool OnlyFromUnverifiedSources =>
            Hits.Count > 0 && Hits.All(h => !h.Source.VerifiesOwnership);
    }
}
