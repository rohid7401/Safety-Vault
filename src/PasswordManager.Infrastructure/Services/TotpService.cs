using System.Security.Cryptography;
using PasswordManager.Core.Interfaces;

namespace PasswordManager.Infrastructure.Services
{
    public class TotpService : ITotpService
    {
        private const int TimeStepSeconds = 30;
        private const int CodeDigits = 6;

        public string GenerateCode(string base32Secret, DateTime? timestamp = null)
        {
            var key = Base32Decode(base32Secret);
            var time = timestamp ?? DateTime.UtcNow;
            var timeStep = GetTimeStep(time);
            var code = ComputeTotp(key, timeStep);
            return code.ToString().PadLeft(CodeDigits, '0');
        }

        public int GetRemainingSeconds()
        {
            var elapsed = DateTimeOffset.UtcNow.ToUnixTimeSeconds() % TimeStepSeconds;
            return TimeStepSeconds - (int)elapsed;
        }

        public bool ValidateCode(string base32Secret, string code, int tolerance = 1)
        {
            var key = Base32Decode(base32Secret);
            var currentStep = GetTimeStep(DateTime.UtcNow);

            for (var i = -tolerance; i <= tolerance; i++)
            {
                var candidate = ComputeTotp(key, currentStep + i);
                if (candidate.ToString().PadLeft(CodeDigits, '0') == code)
                    return true;
            }

            return false;
        }

        private static long GetTimeStep(DateTime time)
        {
            var unixTime = new DateTimeOffset(time).ToUnixTimeSeconds();
            return unixTime / TimeStepSeconds;
        }

        private static int ComputeTotp(byte[] key, long timeStep)
        {
            var timeBytes = BitConverter.GetBytes(timeStep);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(timeBytes);

            using var hmac = new HMACSHA1(key);
            var hash = hmac.ComputeHash(timeBytes);

            var offset = hash[^1] & 0x0F;
            var binaryCode =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

            return binaryCode % (int)Math.Pow(10, CodeDigits);
        }

        private static byte[] Base32Decode(string base32)
        {
            base32 = base32.Trim().ToUpperInvariant().Replace(" ", "").TrimEnd('=');
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            var bits = 0;
            var value = 0;
            var output = new List<byte>();

            foreach (var c in base32)
            {
                var idx = alphabet.IndexOf(c);
                if (idx < 0)
                    throw new FormatException($"Invalid Base32 character: '{c}'");

                value = (value << 5) | idx;
                bits += 5;

                if (bits >= 8)
                {
                    bits -= 8;
                    output.Add((byte)(value >> bits));
                    value &= (1 << bits) - 1;
                }
            }

            return output.ToArray();
        }
    }
}
