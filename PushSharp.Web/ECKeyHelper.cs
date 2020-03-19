using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace PushSharp.Web
{
    internal static class ECKeyHelper
    {
        public static ECPrivateKeyParameters GetPrivateKey(byte[] privateKey)
        {
            Asn1Object version = new DerInteger(1);
            Asn1Object derEncodedKey = new DerOctetString(privateKey);
            Asn1Object keyTypeParameters = new DerTaggedObject(0, new DerObjectIdentifier("1.2.840.10045.3.1.7"));

            Asn1Object derSequence = new DerSequence(version, derEncodedKey, keyTypeParameters);

            var base64EncodedDerSequence = Convert.ToBase64String(derSequence.GetDerEncoded());
            var pemKey = "-----BEGIN EC PRIVATE KEY-----\n";
            pemKey += base64EncodedDerSequence;
            pemKey += "\n-----END EC PRIVATE KEY----";

            using (var reader = new StringReader(pemKey))
            {
                var pemReader = new PemReader(reader);
                var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                return (ECPrivateKeyParameters)keyPair.Private;
            }
        }
    }
}
