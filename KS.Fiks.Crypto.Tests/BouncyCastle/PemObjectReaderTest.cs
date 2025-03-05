using KS.Fiks.Crypto.BouncyCastle;
using Shouldly;
using Xunit;

namespace KS.Fiks.Crypto.Tests.BouncyCastle
{
    public class PemObjectReaderTest
    {
        [Fact(DisplayName = "Extract PEM object from Stream")]
        public void ReadFromStream()
        {
            using (var pemStream = TestDataUtil.GetContentStreamFromResource("fiks_demo_public.pem"))
            {
                var pemObject = PemObjectReader.ReadPem(pemStream);
                pemObject.ShouldNotBeNull();
                pemObject.Type.ShouldBe("CERTIFICATE");
            }
        }

        [Fact(DisplayName = "Extract PEM object from string")]
        public void ReadFromString()
        {
            var privateKeyString = TestDataUtil.GetContentFromResource("fiks_demo_private.pem");
            var pemObject = PemObjectReader.ReadPem(privateKeyString);
            pemObject.ShouldNotBeNull();
            pemObject.Type.ShouldBe("PRIVATE KEY");
        }
    }
}