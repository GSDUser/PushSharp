using System;

namespace PushSharp.Web
{
    internal static class UrlBase64Encoder
    {
        /// <summary>
        /// Decodes a url-safe base64 string into bytes
        /// </summary>
        public static byte[] Decode(string base64)
        {
            base64 = base64.Replace('-', '+').Replace('_', '/');

            while (base64.Length % 4 != 0)
            {
                base64 += "=";
            }

            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Encodes bytes into url-safe base64 string
        /// </summary>
        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }
    }
}