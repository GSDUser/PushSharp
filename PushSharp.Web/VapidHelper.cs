using System;
using System.Collections.Generic;

namespace PushSharp.Web
{
    public static class VapidHelper
    {
        private const int DEFAULT_EXPIRATION = 43200;

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
            string privateKey, long expiration = -1)
        {
            ValidateAudience(audience);
            ValidateSubject(subject);
            ValidatePublicKey(publicKey);
            ValidatePrivateKey(privateKey);

            if (expiration == -1)
            {
                expiration = UnixTimeNow() + DEFAULT_EXPIRATION;
            }
            else
            {
                ValidateExpiration(expiration);
            }

            var header = new Dictionary<string, object> { { "typ", "JWT" }, { "alg", "ES256" } };

            var jwtPayload = new Dictionary<string, object> { { "aud", audience }, { "exp", expiration }, { "sub", subject } };

            var decodedPrivateKey = UrlBase64Encoder.Decode(privateKey);
            var signingKey = ECKeyHelper.GetPrivateKey(decodedPrivateKey);

            var signer = new JwsSigner(signingKey);
            var token = signer.GenerateSignature(header, jwtPayload);

            return $"vapid t={token}, k={publicKey}";
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

        private static void ValidateExpiration(long expiration)
        {
            if (expiration <= UnixTimeNow())
            {
                throw new ArgumentException("Vapid expiration must be a unix timestamp in the future.");
            }
        }

        private static long UnixTimeNow()
        {
            var timeSpan = DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0);
            return (long)timeSpan.TotalSeconds;
        }
    }
}
