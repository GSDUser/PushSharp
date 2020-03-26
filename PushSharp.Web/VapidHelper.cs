using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace PushSharp.Web
{
    public static class VapidHelper
    {
        private const int DEFAULT_EXPIRATION = 43200; //12 hours

        /// <summary>
        /// This method takes the required VAPID parameters and returns the required
        /// header to be added to a Web Push Protocol Request.
        /// </summary>
        /// <param name="audience">This must be the origin of the push service.</param>
        /// <param name="subject">This should be a URL or a 'mailto:' email address</param>
        /// <param name="publicKey">The VAPID public key as a base64 encoded string</param>
        /// <param name="privateKey">The VAPID private key as a base64 encoded string</param>
        /// <param name="expiration">The expiration of the VAPID JWT.</param>
        /// <returns>Authorization header value.</returns>
        public static string GetVapidAuthenticationHeader(string audience, string subject, string publicKey,
            string privateKey, DateTime? expiration = null)
        {
            ValidateAudience(audience);
            ValidateSubject(subject);
            ValidatePublicKey(publicKey);
            ValidatePrivateKey(privateKey);

            if (!expiration.HasValue)
            {
                expiration = DateTime.UtcNow.AddSeconds(DEFAULT_EXPIRATION);
            }
            else
            {
                ValidateExpiration(expiration.Value);
            }

            var decodedPrivateKey = UrlBase64Encoder.Decode(privateKey);
            var decodedPublicKey = UrlBase64Encoder.Decode(publicKey);

            var privateECDsa = GetECDsaByPrivateKey(decodedPublicKey, decodedPrivateKey);

            //Create JWT token and sign it using ECDsa
            var securityToken = new JwtSecurityToken(
                audience: audience,
                claims: new[] { new Claim("sub", subject) },
                expires: expiration,
                signingCredentials: new SigningCredentials(new ECDsaSecurityKey(privateECDsa), SecurityAlgorithms.EcdsaSha256));
            
             var jwToken = new JwtSecurityTokenHandler().WriteToken(securityToken);

            return $"vapid t={jwToken}, k={publicKey}";
        }

        public static void ValidateAudience(string audience)
        {
            if (string.IsNullOrWhiteSpace(audience))
            {
                throw new ArgumentException("The audience value must be a string containing the origin of a push service.");
            }

            if (!Uri.IsWellFormedUriString(audience, UriKind.Absolute))
            {
                throw new ArgumentException("VAPID audience is not an absolute url.");
            }
        }

        public static void ValidateSubject(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject))
            {
                throw new ArgumentException("The subject value must be a string containing a url or mailto: address.");
            }

            if (!subject.StartsWith("mailto:"))
            {
                if (!Uri.IsWellFormedUriString(subject, UriKind.Absolute))
                {
                    throw new ArgumentException("Subject is not a valid URL or mailto address");
                }
            }
        }

        public static void ValidatePublicKey(string publicKey)
        {
            if (string.IsNullOrEmpty(publicKey))
            {
                throw new ArgumentException("Valid public key not set.");
            }

            var decodedPublicKey = UrlBase64Encoder.Decode(publicKey);

            if (decodedPublicKey.Length != 65)
            {
                throw new ArgumentException("Vapid public key must be 65 characters long when decoded.");
            }
        }

        public static void ValidatePrivateKey(string privateKey)
        {
            if (string.IsNullOrEmpty(privateKey))
            {
                throw new ArgumentException("Valid private key not set.");
            }

            var decodedPrivateKey = UrlBase64Encoder.Decode(privateKey);

            if (decodedPrivateKey.Length != 32)
            {
                throw new ArgumentException("Vapid private key should be 32 bytes long when decoded.");
            }
        }

        private static CngKey ImportPrivCngKey(byte[] pubKey, byte[] privKey)
        {
            // to import keys to CngKey in ECCPublicKeyBlob and ECCPrivateKeyBlob format, keys should be form in specific formats as noted here :
            // https://stackoverflow.com/a/24255090
            // magic prefixes : https://referencesource.microsoft.com/#system.core/System/Security/Cryptography/BCryptNative.cs,fde0749a0a5f70d8,references
            var keyType = new byte[] { 0x45, 0x43, 0x53, 0x32 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };

            var key = pubKey.Skip(1);

            var keyImport = keyType.Concat(keyLength).Concat(key).Concat(privKey).ToArray();

            var cngKey = CngKey.Import(keyImport, CngKeyBlobFormat.EccPrivateBlob);
            return cngKey;
        }

        private static ECDsa GetECDsaByPrivateKey(byte[] publicKey, byte[] privateKey)
        {
            var cngKey = ImportPrivCngKey(publicKey, privateKey);
            var ecDsaCng = new ECDsaCng(cngKey);
            ecDsaCng.HashAlgorithm = CngAlgorithm.ECDsaP256;
            return ecDsaCng;
        }

        private static void ValidateExpiration(DateTime expiration)
        {
            if (expiration <= DateTime.UtcNow)
            {
                throw new ArgumentException("Vapid expiration must be a unix timestamp in the future.");
            }
        }
    }
}
