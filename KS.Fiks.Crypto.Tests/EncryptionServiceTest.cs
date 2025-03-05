using System.IO;
using System.Text;
using KS.Fiks.Crypto.BouncyCastle;
using Shouldly;
using Xunit;

namespace KS.Fiks.Crypto.Tests
{
    public class EncryptionServiceTest
    {
        [Fact(DisplayName = "Create using PEM string")]
        public void CreatePem()
        {
            EncryptionService.Create(TestDataUtil.ReadPublicCertificatePem()).ShouldNotBeNull();
        }

        [Fact(DisplayName = "Create using X509 certificate")]
        public void CreateCert()
        {
            EncryptionService.Create(X509CertificateReader.ExtractCertificate(TestDataUtil.ReadPublicCertificatePem()))
                .ShouldNotBeNull();
        }

        [Fact(DisplayName = "Encrypt data")]
        public void Encrypt()
        {
            var testDataContent = TestDataUtil.ReadTestData();
            var testData = Encoding.UTF8.GetBytes(testDataContent);

            var encryptionService = CreateEncryptionService();
            var decryptionService = CreateDecryptionService();
            byte[] encryptedData = null;
            using (var encryptedStream = new MemoryStream())
            using (var unencryptedStream = new MemoryStream(testData))
            {
                encryptionService.Encrypt(unencryptedStream, encryptedStream);
                encryptedData = encryptedStream.ToArray();
            }

            using (var encryptedStream = new MemoryStream(encryptedData))
            using (var decryptedStream = decryptionService.Decrypt(encryptedStream))
            using (var decryptionBuffer = new MemoryStream())
            {
                decryptedStream.CopyTo(decryptionBuffer);
                var decryptedData = decryptionBuffer.ToArray();
                var decryptedString = Encoding.UTF8.GetString(decryptedData);
                decryptedString.ShouldBe(testDataContent);
            }
        }

        private static IEncryptionService CreateEncryptionService()
        {
            return EncryptionService.Create(TestDataUtil.ReadPublicCertificate());
        }

        private static IDecryptionService CreateDecryptionService()
        {
            return DecryptionService.Create(TestDataUtil.ReadPrivateKey());
        }
    }
}