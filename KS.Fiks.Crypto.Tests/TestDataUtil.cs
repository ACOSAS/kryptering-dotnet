using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using KS.Fiks.Crypto.BouncyCastle;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace KS.Fiks.Crypto.Tests
{
    public static class TestDataUtil
    {
        private const string TextFileResource = "LoremIpsum.txt";
        private const string PrivateKeyResource = "fiks_demo_private.pem";
        private const string InvalidKeyResource = "invalid.pem";
        private const string PublicCertificateResource = "fiks_demo_public.pem";

        public static string ReadTestData()
        {
            return GetContentFromResource(TextFileResource);
        }

        public static string ReadPrivateKeyPem()
        {
            return GetContentFromResource(PrivateKeyResource);
        }
        
        public static string ReadInvalidPrivateKeyPem()
        {
            return GetContentFromResource(InvalidKeyResource);
        }

        public static AsymmetricKeyParameter ReadPrivateKey()
        {
            return AsymmetricKeyParameterReader.ExtractPrivateKey(ReadPrivateKeyPem());
        }
        
        public static AsymmetricKeyParameter ReadInvalidPrivateKey()
        {
            return AsymmetricKeyParameterReader.ExtractPrivateKey(ReadInvalidPrivateKeyPem());
        }

        public static string ReadPublicCertificatePem()
        {
            return GetContentFromResource(PublicCertificateResource);
        }

        public static X509Certificate ReadPublicCertificate()
        {
            return X509CertificateReader.ExtractCertificate(ReadPublicCertificatePem());
        }

        public static string GetContentFromResource(string resource)
        {
            using (var stream = GetContentStreamFromResource(resource))
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        public static Stream GetContentStreamFromResource(string resource)
        {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceName = assembly.GetManifestResourceNames().Single(str =>
                str.EndsWith(resource, StringComparison.CurrentCulture));
            return assembly.GetManifestResourceStream(resourceName);
        }
    }
}