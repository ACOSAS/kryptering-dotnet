using System;
using System.IO;
using System.Text;
using Shouldly;
using Xunit;

namespace KS.Fiks.Crypto.Tests
{
    public class DecryptionServiceTest
    {
        [Fact(DisplayName = "Create using PEM")]
        public void CreatePem()
        {
            DecryptionService.Create(TestDataUtil.ReadPrivateKeyPem()).ShouldNotBeNull();
        }

        [Fact(DisplayName = "Create using private key")]
        public void CreatePrivateKey()
        {
            DecryptionService.Create(TestDataUtil.ReadPrivateKey()).ShouldNotBeNull();
        }

        [Fact(DisplayName = "Decryption")]
        public void Decrypt()
        {
            var unencryptedDataChunk = TestDataUtil.GetContentFromResource("UnencryptedData.txt");
            var encryptedData = Encrypt(unencryptedDataChunk);
            var cryptoService = CreateDecryptionService();
            using (var encryptedDataStream = new MemoryStream(encryptedData))
            {
                using (var decryptedDataStream = cryptoService.Decrypt(encryptedDataStream))
                using (var decryptedStuff = new MemoryStream())
                {
                    decryptedDataStream.CopyTo(decryptedStuff);
                    var decryptedDataChunk = decryptedStuff.ToArray();
                    var decryptedDataString = Encoding.UTF8.GetString(decryptedDataChunk)?.TrimEnd();

                    decryptedDataString.Equals(unencryptedDataChunk, StringComparison.InvariantCulture)
                        .ShouldBeTrue();
                }
            }
        }

        [Fact(DisplayName = "Decryption with multiple private keys")]
        public void DecryptWithInvalidAndValidPrivateKey()
        {
            var unencryptedDataChunk = TestDataUtil.GetContentFromResource("UnencryptedData.txt");
            var encryptedData = Encrypt(unencryptedDataChunk);
            var cryptoService = DecryptionService.Create(new[]
                {TestDataUtil.ReadInvalidPrivateKey(), TestDataUtil.ReadPrivateKey() });
            using var encryptedDataStream = new MemoryStream(encryptedData);
            using var decryptedDataStream = cryptoService.Decrypt(encryptedDataStream);
            using var decryptedStuff = new MemoryStream();

            decryptedDataStream.CopyTo(decryptedStuff);
            var decryptedDataChunk = decryptedStuff.ToArray();
            var decryptedDataString = Encoding.UTF8.GetString(decryptedDataChunk).TrimEnd();

            decryptedDataString.Equals(unencryptedDataChunk, StringComparison.InvariantCulture)
                .ShouldBeTrue();
        }

        private static byte[] Encrypt(string unencryptedData)
        {
            IEncryptionService encryptionService = EncryptionService.Create(TestDataUtil.ReadPublicCertificate());
            using (var unencryptedStream = new MemoryStream(Encoding.UTF8.GetBytes(unencryptedData)))
            using (var encryptedOutStream = new MemoryStream())
            {
                encryptionService.Encrypt(unencryptedStream, encryptedOutStream);
                return encryptedOutStream.ToArray();
            }
        }

        private static IDecryptionService CreateDecryptionService()
        {
            return DecryptionService.Create(TestDataUtil.ReadPrivateKey());
        }
    }
}