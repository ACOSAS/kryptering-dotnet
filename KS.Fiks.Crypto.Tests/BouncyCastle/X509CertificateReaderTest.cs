using KS.Fiks.Crypto.BouncyCastle;
using Org.BouncyCastle.Math;
using Shouldly;
using Xunit;

namespace KS.Fiks.Crypto.Tests.BouncyCastle
{
    public class X509CertificateReaderTest
    {
        private const string IssuerDN = "C=NO,ST=kryptering,L=kryptering,O=kryptering,OU=kryptering,CN=kryptering";
        private const string SubjectDN = "C=NO,ST=kryptering,L=kryptering,O=kryptering,OU=kryptering,CN=kryptering";

        [Fact(DisplayName = "Extract certificate from Stream")]
        public void ReadCertificateFromStream()
        {
            using (var pemStream = TestDataUtil.GetContentStreamFromResource("fiks_demo_public.pem"))
            {
                var certificate = X509CertificateReader.ExtractCertificate(pemStream);
                certificate.ShouldNotBeNull();
                certificate.IssuerDN.ToString().ShouldBe(IssuerDN);
                certificate.SubjectDN.ToString().ShouldBe(SubjectDN);
            }
        }

        [Fact(DisplayName = "Extract certificate from string")]
        public void ReadValidCertificate()
        {
            var pemFile = TestDataUtil.GetContentFromResource("fiks_demo_public.pem");
            var certificate = X509CertificateReader.ExtractCertificate(pemFile);
            certificate.ShouldNotBeNull();
            certificate.IssuerDN.ToString().ShouldBe(IssuerDN);
            certificate.SubjectDN.ToString().ShouldBe(SubjectDN);
            certificate.SigAlgName.ShouldBe("SHA-256withRSA");
            certificate.SerialNumber.ShouldBe(new BigInteger("9386322399984342181"));
        }
    }
}