using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KS.Fiks.Crypto.BouncyCastle;
using Org.BouncyCastle.Crypto;

namespace KS.Fiks.Crypto
{
    /// <summary>
    /// Service used for decryption of AES encrypted CRM encoded data
    /// </summary>
    public class DecryptionService : IDecryptionService
    {
        private readonly IReadOnlyCollection<AsymmetricKeyParameter> _privateKeys;

        internal DecryptionService(AsymmetricKeyParameter privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }

            _privateKeys = new List<AsymmetricKeyParameter> {privateKey};
        }
        
        internal DecryptionService(IEnumerable<AsymmetricKeyParameter> privateKeys)
        {

            if (privateKeys == null)
            {
                throw new ArgumentNullException(nameof(privateKeys));
            }

            _privateKeys = privateKeys.ToList();
        }

        /// <summary>
        /// Creates a new instance using the provided private key for decryption
        /// </summary>
        /// <param name="privateKey">the private key to be used for decryption</param>
        /// <returns>a new instance of the DecryptionService</returns>
        public static DecryptionService Create(
            AsymmetricKeyParameter privateKey)
        {
            return new DecryptionService(privateKey);
        }
        
        /// <summary>
        /// Creates a new instance using the provided private key for decryption
        /// </summary>
        /// <param name="pemStringPrivateKeys"></param>
        /// <returns>a new instance of the DecryptionService</returns>
        public static DecryptionService Create(
            IEnumerable<AsymmetricKeyParameter> pemStringPrivateKeys)
        {
            return new DecryptionService(pemStringPrivateKeys);
        }

        /// <summary>
        /// Creates a new instance using the provided DER encoded PEM as private key for decryption
        /// </summary>
        /// <param name="pemStringPrivateKey">a DER encoded PEM containing a private key</param>
        /// <returns>a new instance of the DecryptionService</returns>
        public static DecryptionService Create(string pemStringPrivateKey)
        {
            return Create(AsymmetricKeyParameterReader.ExtractPrivateKey(pemStringPrivateKey));
        }

        public static DecryptionService Create(IEnumerable<string> pemStringPrivateKey)
        {
            return Create(pemStringPrivateKey.Select(AsymmetricKeyParameterReader.ExtractPrivateKey));
        }

        public Stream Decrypt(Stream encryptedStream)
        {
            if (!encryptedStream.CanRead)
            {
                throw new ArgumentException("Stream is not readable", nameof(encryptedStream));
            }

            return DecryptStreamConverter.Decrypt(_privateKeys, encryptedStream);
        }
    }
}