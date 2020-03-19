using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace PushSharp.Web
{
    internal class JwsSigner
    {
        private readonly ECPrivateKeyParameters _privateKey;

        public JwsSigner(ECPrivateKeyParameters privateKey)
        {
            _privateKey = privateKey;
        }

        /// <summary>
        /// Generates a Jws Signature.
        /// </summary>
        public string GenerateSignature(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var securedInput = SecureInput(header, payload);
            var message = Encoding.UTF8.GetBytes(securedInput);

            var hashedMessage = Sha256Hash(message);

            var signer = new ECDsaSigner();
            signer.Init(true, _privateKey);
            var results = signer.GenerateSignature(hashedMessage);

            // Concated to create signature
            var a = results[0].ToByteArrayUnsigned();
            var b = results[1].ToByteArrayUnsigned();

            // a,b are required to be exactly the same length of bytes
            if (a.Length != b.Length)
            {
                var largestLength = Math.Max(a.Length, b.Length);
                a = ByteArrayPadLeft(a, largestLength);
                b = ByteArrayPadLeft(b, largestLength);
            }

            var signature = UrlBase64Encoder.Encode(a.Concat(b).ToArray());
            return $"{securedInput}.{signature}";
        }

        private static string SecureInput(Dictionary<string, object> header, Dictionary<string, object> payload)
        {
            var encodeHeader = UrlBase64Encoder.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header)));
            var encodePayload = UrlBase64Encoder.Encode(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload)));

            return $"{encodeHeader}.{encodePayload}";
        }

        private static byte[] ByteArrayPadLeft(byte[] src, int size)
        {
            var dst = new byte[size];
            var startAt = dst.Length - src.Length;
            Array.Copy(src, 0, dst, startAt, src.Length);
            return dst;
        }

        private static byte[] Sha256Hash(byte[] message)
        {
            using (var sha256Hasher = SHA256.Create())
            {
                return sha256Hasher.ComputeHash(message);
            }
        }
    }
}
