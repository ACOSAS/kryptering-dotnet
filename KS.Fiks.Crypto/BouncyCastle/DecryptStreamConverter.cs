using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;

namespace KS.Fiks.Crypto.BouncyCastle
{
    public static class DecryptStreamConverter
    {
        public static Stream Decrypt(AsymmetricKeyParameter privateKey, Stream encryptedStream)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }

            var recipientInformation = GetRecipientInformation(encryptedStream);
            return recipientInformation.GetContentStream(privateKey).ContentStream;
        }

        public static Stream Decrypt(IReadOnlyCollection<AsymmetricKeyParameter> privateKeys, Stream encryptedStream)
        {
            if (privateKeys == null)
            {
                throw new ArgumentNullException(nameof(privateKeys));
            }

            var recipientInformation = GetRecipientInformation(encryptedStream);

            using (var keysIterator = privateKeys.GetEnumerator())
            {
                while (true)
                {
                    try
                    {
                        var cs = recipientInformation.GetContentStream(keysIterator.Current);
                        return cs.ContentStream;
                    }
                    catch (Exception)
                    {
                        if (!keysIterator.MoveNext())
                        {
                            throw;
                        }
                    }
                }
            }
        }

        private static RecipientInformation GetRecipientInformation(Stream encryptedStream)
        {
            if (encryptedStream == null)
            {
                throw new ArgumentNullException(nameof(encryptedStream));
            }

            var cmsEnvelopedDataParser = new CmsEnvelopedDataParser(new BufferedStream(encryptedStream, 1024 * 1024));
            var encryptionAlgorithm = cmsEnvelopedDataParser.EncryptionAlgOid;
            if (encryptionAlgorithm != CmsEnvelopedGenerator.Aes256Cbc)
            {
                throw new UnexpectedEncryptionAlgorithmException(CmsEnvelopedGenerator.Aes256Cbc, encryptionAlgorithm);
            }

            var recipientInformationStore = cmsEnvelopedDataParser.GetRecipientInfos();
            if (recipientInformationStore.Count < 1)
            {
                throw new UnexpectedRecipientCountException(recipientInformationStore.Count);
            }

            var recipients = recipientInformationStore.GetRecipients().Cast<RecipientInformation>();
            return recipients.First();
        }
    }
}