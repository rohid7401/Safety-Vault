﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PasswordManager.Core.Interfaces;
using System.Security.Cryptography;

namespace PasswordManager.Infrastructure.Encryption
{
    public class AesService : IAesService
    {
        public (string CipherText, string IV) Encrypt(string plainText, string key)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.GenerateIV();
            var iv = Convert.ToBase64String(aes.IV);

            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var memoryStream = new MemoryStream();
            using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            using (var streamWriter = new StreamWriter(cryptoStream))
            {
                streamWriter.Write(plainText);
            }
            var cipherText = Convert.ToBase64String(memoryStream.ToArray());
            return (cipherText, iv);
        }


        public string Decrypt(string cipherText, string key, string iv)
        {
            using var aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.IV = Convert.FromBase64String(iv);

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var memoryStream = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            using var streamReader = new StreamReader(cryptoStream);
            {
                return streamReader.ReadToEnd();
            }
        }
    }
}
