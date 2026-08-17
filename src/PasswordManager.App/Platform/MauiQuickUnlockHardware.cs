using PasswordManager.UI.Services;

#if ANDROID
using System.Security.Cryptography;
using Android.Runtime;
using Android.Security.Keystore;
using AndroidX.Biometric;
using AndroidX.Fragment.App;
using Java.Security;
using Javax.Crypto;
using Javax.Crypto.Spec;
using Microsoft.Maui.Storage;
#endif

namespace PasswordManager.App.Platform
{
    /// <summary>
    /// The hardware half of quick unlock.
    ///
    /// <para>The secret itself is a random 32 bytes kept encrypted in Preferences. What makes it
    /// hardware-held is the key that encrypts it: an AES key generated inside the Android
    /// Keystore, which the chip will use on request and never hand over. Copying the app's data
    /// off the phone therefore yields a ciphertext nobody can open elsewhere — which is the
    /// entire reason a four-digit PIN is safe here and would not be otherwise.</para>
    ///
    /// <para>Every alias and preferences key below carries the vault id. An earlier version used
    /// fixed names, and the result was that enrolling a second account overwrote the first
    /// account's secret while leaving its slot file in place — a slot that counted attempts
    /// against a secret that no longer existed, and a <c>Forget</c> that wiped every account at
    /// once. Scoping is not a nicety here; it is what makes more than one vault possible.</para>
    /// </summary>
    public class MauiQuickUnlockHardware : IQuickUnlockHardware
    {
#if !ANDROID
        public QuickUnlockCapability Capability => QuickUnlockCapability.None;

        public BiometricAvailability BiometricStatus => BiometricAvailability.NoStrongSensor;

        public bool HasSecret(string vaultId) => false;

        public Task<byte[]?> EnrollAsync(string vaultId, bool biometric) => Task.FromResult<byte[]?>(null);

        public Task<byte[]?> RetrieveAsync(string vaultId, bool biometric, string promptTitle,
                                           string promptSubtitle, string cancelLabel)
            => Task.FromResult<byte[]?>(null);

        public void Forget(string vaultId) { }
#else
        private const string StoreName = "AndroidKeyStore";
        private const int SecretBytes = 32;
        private const int GcmTagBits = 128;

        /// <summary>The Keystore alias for one vault's key. Scoped, never shared.</summary>
        private static string Alias(string vaultId, bool biometric) =>
            $"safetyvault.quick.{(biometric ? "bio" : "pin")}.{vaultId}";

        /// <summary>Where the wrapped secret lives. Only ever a ciphertext.</summary>
        private static string BlobKey(string vaultId, bool biometric) =>
            $"quick_secret_{(biometric ? "bio" : "pin")}_{vaultId}";

        public QuickUnlockCapability Capability
        {
            get
            {
                // Class 3 ("strong") only. The weak classes cannot gate a Keystore key, so
                // accepting them would mean a prompt that looks like protection and gates nothing.
                if (BiometricStatus == BiometricAvailability.Available)
                    return QuickUnlockCapability.Biometric;

                // No usable biometric. A PIN slot is still safe as long as the key really lives
                // in the chip — if it does not, the PIN is ten thousand guesses and we say no.
                return HasSecureHardware() ? QuickUnlockCapability.PinOnly : QuickUnlockCapability.None;
            }
        }

        /// <summary>
        /// Distinguishes the reasons a strong biometric is not on offer, so the settings screen
        /// can explain instead of just showing one button fewer. The common case by far is
        /// <see cref="BiometricAvailability.NoneEnrolled"/> on a phone whose only enrolled
        /// biometric is a Class 2 face — which the user reasonably reads as "I have face unlock,
        /// why is this app ignoring it".
        /// </summary>
        public BiometricAvailability BiometricStatus
        {
            get
            {
                var manager = BiometricManager.From(Android.App.Application.Context);
                return manager.CanAuthenticate(BiometricManager.Authenticators.BiometricStrong) switch
                {
                    BiometricManager.BiometricSuccess => BiometricAvailability.Available,
                    BiometricManager.BiometricErrorNoneEnrolled => BiometricAvailability.NoneEnrolled,
                    BiometricManager.BiometricErrorNoHardware => BiometricAvailability.NoStrongSensor,
                    _ => BiometricAvailability.Unavailable,
                };
            }
        }

        /// <summary>
        /// Asks the Keystore for a throwaway key and inspects where it ended up. There is no way
        /// to ask the question directly, and assuming secure hardware is exactly the assumption
        /// that must not be made silently.
        /// </summary>
        private static bool HasSecureHardware()
        {
            const string probeAlias = "safetyvault.quick.probe";
            try
            {
                var generator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, StoreName)!;
                generator.Init(new KeyGenParameterSpec.Builder(
                        probeAlias, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                    .SetBlockModes(KeyProperties.BlockModeGcm!)
                    .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone!)
                    .Build());
                generator.GenerateKey();

                var store = KeyStore.GetInstance(StoreName)!;
                store.Load(null);
                var key = store.GetKey(probeAlias, null);
                var factory = SecretKeyFactory.GetInstance(key!.Algorithm!, StoreName)!;
                var info = (KeyInfo)factory.GetKeySpec(key.JavaCast<ISecretKey>(), Java.Lang.Class.FromType(typeof(KeyInfo)))!;

                bool secure;
                if (Android.OS.Build.VERSION.SdkInt >= Android.OS.BuildVersionCodes.S)
                    secure = info.SecurityLevel != (int)KeyStoreSecurityLevel.Software;
                else
#pragma warning disable CA1422 // The replacement above only exists from API 31.
                    secure = info.IsInsideSecureHardware;
#pragma warning restore CA1422

                store.DeleteEntry(probeAlias);
                return secure;
            }
            catch (Exception)
            {
                // A Keystore that will not even make a key is not one to trust a PIN to.
                return false;
            }
        }

        /// <summary>
        /// True only when both halves of the platform secret survive: the wrapped blob and the
        /// Keystore key that opens it. Either one alone opens nothing, so either one missing means
        /// the slot it belongs to is finished.
        /// </summary>
        public bool HasSecret(string vaultId)
        {
            foreach (var biometric in new[] { true, false })
            {
                if (string.IsNullOrEmpty(Preferences.Default.Get(BlobKey(vaultId, biometric), string.Empty)))
                    continue;

                try
                {
                    var store = KeyStore.GetInstance(StoreName)!;
                    store.Load(null);
                    if (store.ContainsAlias(Alias(vaultId, biometric))) return true;
                }
                catch (Exception) { }
            }

            return false;
        }

        public async Task<byte[]?> EnrollAsync(string vaultId, bool biometric)
        {
            try
            {
                CreateKeystoreKey(vaultId, biometric);

                var secret = RandomNumberGenerator.GetBytes(SecretBytes);
                var cipher = NewCipher();
                var key = LoadKey(vaultId, biometric);
                if (key is null) return null;

                cipher.Init(Javax.Crypto.CipherMode.EncryptMode, key);

                // Encrypting under a user-auth key needs the same authorisation as decrypting,
                // so enrolment prompts once too — which also proves the finger works before
                // anything comes to depend on it.
                if (biometric)
                {
                    var authorized = await AuthorizeAsync(cipher, promptTitle: null);
                    if (authorized is null) return null;
                    cipher = authorized;
                }

                var wrapped = cipher.DoFinal(secret)!;
                var iv = cipher.GetIV()!;

                Preferences.Default.Set(BlobKey(vaultId, biometric),
                    Convert.ToBase64String(iv) + ":" + Convert.ToBase64String(wrapped));

                return secret;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<byte[]?> RetrieveAsync(string vaultId, bool biometric, string promptTitle,
                                                 string promptSubtitle, string cancelLabel)
        {
            try
            {
                var blob = Preferences.Default.Get(BlobKey(vaultId, biometric), string.Empty);
                if (string.IsNullOrEmpty(blob)) return null;

                var parts = blob.Split(':');
                if (parts.Length != 2) return null;
                var iv = Convert.FromBase64String(parts[0]);
                var wrapped = Convert.FromBase64String(parts[1]);

                var key = LoadKey(vaultId, biometric);
                // Gone means the platform destroyed it — new fingerprints enrolled, most likely.
                // Failing closed here is the behaviour the design depends on.
                if (key is null) return null;

                var cipher = NewCipher();
                cipher.Init(Javax.Crypto.CipherMode.DecryptMode, key, new GCMParameterSpec(GcmTagBits, iv));

                if (biometric)
                {
                    var authorized = await AuthorizeAsync(cipher, promptTitle, promptSubtitle, cancelLabel);
                    if (authorized is null) return null;
                    cipher = authorized;
                }

                return cipher.DoFinal(wrapped);
            }
            catch (KeyPermanentlyInvalidatedException)
            {
                // Said out loud rather than swallowed with everything else: this is the specific
                // case of "the fingerprints changed". The blob is dropped so the slot is seen as
                // dead on the next look, rather than lingering as a button that cannot work.
                Preferences.Default.Remove(BlobKey(vaultId, biometric));
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public void Forget(string vaultId)
        {
            foreach (var biometric in new[] { true, false })
            {
                Preferences.Default.Remove(BlobKey(vaultId, biometric));
                try
                {
                    var store = KeyStore.GetInstance(StoreName)!;
                    store.Load(null);
                    store.DeleteEntry(Alias(vaultId, biometric));
                }
                catch (Exception) { }
            }
        }

        private static Cipher NewCipher() => Cipher.GetInstance(
            $"{KeyProperties.KeyAlgorithmAes}/{KeyProperties.BlockModeGcm}/{KeyProperties.EncryptionPaddingNone}")!;

        private static IKey? LoadKey(string vaultId, bool biometric)
        {
            var store = KeyStore.GetInstance(StoreName)!;
            store.Load(null);
            return store.GetKey(Alias(vaultId, biometric), null);
        }

        private static void CreateKeystoreKey(string vaultId, bool biometric)
        {
            var generator = KeyGenerator.GetInstance(KeyProperties.KeyAlgorithmAes, StoreName)!;

            var builder = new KeyGenParameterSpec.Builder(
                    Alias(vaultId, biometric), KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                .SetBlockModes(KeyProperties.BlockModeGcm!)
                .SetEncryptionPaddings(KeyProperties.EncryptionPaddingNone!)
                // Every wrap gets a fresh IV from the Keystore itself.
                .SetRandomizedEncryptionRequired(true)!;

            if (biometric)
            {
                builder = builder.SetUserAuthenticationRequired(true)!;

                // The condition that makes a new fingerprint useless against the old slot: adding
                // one destroys this key, so the secret becomes unrecoverable and the slot fails
                // closed instead of quietly admitting someone new.
                if (Android.OS.Build.VERSION.SdkInt >= Android.OS.BuildVersionCodes.N)
                    builder = builder.SetInvalidatedByBiometricEnrollment(true)!;

                if (Android.OS.Build.VERSION.SdkInt >= Android.OS.BuildVersionCodes.R)
                    builder = builder.SetUserAuthenticationParameters(
                        0, (int)KeyPropertiesAuthType.BiometricStrong)!;
            }

            // Best effort: a dedicated security chip where there is one, the TEE otherwise. Not
            // fatal, because HasSecureHardware has already refused the software-only case.
            if (Android.OS.Build.VERSION.SdkInt >= Android.OS.BuildVersionCodes.P)
            {
                try
                {
                    generator.Init(builder.SetIsStrongBoxBacked(true)!.Build());
                    generator.GenerateKey();
                    return;
                }
                catch (StrongBoxUnavailableException) { }
                catch (ProviderException) { }
            }

            generator.Init(builder.SetIsStrongBoxBacked(false)!.Build());
            generator.GenerateKey();
        }

        /// <summary>
        /// Shows the system prompt and returns the Cipher it authorised. The Cipher that comes
        /// back out of the CryptoObject is the one that must be used: the authorisation is bound
        /// to that instance, not to the key in general, so a second Cipher would be refused.
        /// </summary>
        private static Task<Cipher?> AuthorizeAsync(Cipher cipher, string? promptTitle,
                                                    string? subtitle = null, string? cancelLabel = null)
        {
            var completion = new TaskCompletionSource<Cipher?>();

            var activity = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity as FragmentActivity;
            if (activity is null)
            {
                completion.SetResult(null);
                return completion.Task;
            }

            MainThread.BeginInvokeOnMainThread(() =>
            {
                try
                {
                    var prompt = new BiometricPrompt(activity,
                        AndroidX.Core.Content.ContextCompat.GetMainExecutor(activity)!,
                        new Callback(completion));

                    var info = new BiometricPrompt.PromptInfo.Builder()
                        .SetTitle(promptTitle ?? "SafetyVault")!
                        .SetSubtitle(subtitle ?? string.Empty)!
                        .SetNegativeButtonText(cancelLabel ?? "Cancel")!
                        .SetAllowedAuthenticators(BiometricManager.Authenticators.BiometricStrong)!
                        .Build();

                    prompt.Authenticate(info, new BiometricPrompt.CryptoObject(cipher));
                }
                catch (Exception)
                {
                    completion.TrySetResult(null);
                }
            });

            return completion.Task;
        }

        private sealed class Callback : BiometricPrompt.AuthenticationCallback
        {
            private readonly TaskCompletionSource<Cipher?> _completion;

            public Callback(TaskCompletionSource<Cipher?> completion) => _completion = completion;

            public override void OnAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result)
                => _completion.TrySetResult(result.CryptoObject?.Cipher);

            // Cancelled, locked out, or no hardware right now — all of them mean "not this way",
            // and the passphrase is still there.
            public override void OnAuthenticationError(int errorCode, Java.Lang.ICharSequence errString)
                => _completion.TrySetResult(null);

            // A finger that did not match. The prompt stays up for another try, so this is not
            // an outcome yet and must not complete the task.
            public override void OnAuthenticationFailed() { }
        }
#endif
    }
}
