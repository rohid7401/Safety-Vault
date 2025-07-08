﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg;


namespace PasswordManager.Infrastructure.Encryption
{
    public class PgpEncryption
    {
        public static void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath)
        {
            using (var publicKeyStream = File.OpenRead(publicKeyPath))
            using (var inputFileStream = File.OpenRead(inputFilePath))
            using (var outputFileStream = File.Create(outputFilePath))
            {
                var publicKey = PgpEncryptionHelper.ReadPublicKey(publicKeyStream);
                var encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256);
                encryptedDataGenerator.AddMethod(publicKey);

                using (var encryptedStream = encryptedDataGenerator.Open(outputFileStream, new byte[4096]))
                {
                    inputFileStream.CopyTo(encryptedStream);
                }
            }
        }

        public static string EncryptString(string plainText, string publicKeyPath)
        {
            using (var publicKeyStream = File.OpenRead(publicKeyPath))
            using (var memoryStream = new MemoryStream())
            {
                var publicKey = PgpEncryptionHelper.ReadPublicKey(publicKeyStream);
                var encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256);
                encryptedDataGenerator.AddMethod(publicKey);

                using (var encryptedStream = encryptedDataGenerator.Open(memoryStream, new byte[4096]))
                using (var streamWriter = new StreamWriter(encryptedStream, Encoding.UTF8))
                {
                    streamWriter.Write(plainText);
                }
                return Convert.ToBase64String(memoryStream.ToArray());
            }
        }
    }
}
