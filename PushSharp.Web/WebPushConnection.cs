using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using LogicSoftware.WebPushEncryption;
using PushSharp.Core;
using PushSharp.Web.Exceptions;

namespace PushSharp.Web
{
    public class WebPushConnection : IServiceConnection<WebPushNotification>
    {
        readonly HttpClient http;
        private static string DefaultTTL = "2419200";

        public WebPushConfiguration Configuration { get; }

        public WebPushConnection(WebPushConfiguration configuration)
        {
            Configuration = configuration;
            http = new HttpClient();

            http.DefaultRequestHeaders.UserAgent.Clear();
            http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("PushSharp", "3.0"));
        }

        public async Task Send(WebPushNotification notification)
        {
            var request = BuildRequest(notification);
            var response = await http.SendAsync(request);

            if (response.StatusCode != HttpStatusCode.Created)
            {
                await ProcessResponseError(response, notification).ConfigureAwait(false);
            }
        }

        private HttpRequestMessage BuildRequest(WebPushNotification notification)
        {
            var subscription = notification.Subscription;
            var json = notification.GetJson();

            /*
                see for details about message encryption 
                https://tools.ietf.org/html/draft-ietf-webpush-encryption-04
                https://developers.google.com/web/updates/2016/03/web-push-encryption
            */
            var encryptedPayload = EncryptPayload(subscription, json);
            
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, subscription.EndPoint);
            if (encryptedPayload != null)
            {
                
                request.Content = new ByteArrayContent(encryptedPayload.Payload);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                request.Content.Headers.ContentLength = encryptedPayload.Payload.Length;
                request.Content.Headers.ContentEncoding.Add("aesgcm");
                request.Headers.Add("Crypto-Key", "dh=" + encryptedPayload.Base64EncodePublicKey());
                request.Headers.Add("Encryption", "salt=" + encryptedPayload.Base64EncodeSalt());
            }

            request.Headers.TryAddWithoutValidation("TTL", DefaultTTL);

            var isGsm = subscription.EndPoint.StartsWith(Configuration.GcmEndPoint, StringComparison.Ordinal);
            if (isGsm)
            {
                if (string.IsNullOrEmpty(Configuration.GcmAPIKey))
                {
                    throw new Exception("GcmAPIKey is required.");
                }
                request.Headers.TryAddWithoutValidation("Authorization", "key=" + Configuration.GcmAPIKey);
            }
            else
            {
                var uri = new Uri(subscription.EndPoint);
                var audience = uri.Scheme + @"://" + uri.Host;

                /*
                    see for details about Web Push VAPID authentication
                    https://tools.ietf.org/html/rfc8292
                    https://developers.google.com/web/fundamentals/push-notifications/web-push-protocol
                    https://blog.mozilla.org/services/2016/08/23/sending-vapid-identified-webpush-notifications-via-mozillas-push-service/
                */
                var vapidHeader = VapidHelper.GetVapidAuthenticationHeader(audience, Configuration.Subject,
                    Configuration.PublicApplicationKey, Configuration.PrivateApplicationKey);
                request.Headers.Add("Authorization", vapidHeader);
            }

            return request;
        }

        private EncryptionResult EncryptPayload(WebPushSubscription subscription, string payload)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return null;
            }

            subscription.Validate();

            var keys = subscription.Keys;

            return Encryptor.Encrypt(keys.P256dh, keys.Auth, payload);
        }

        async Task ProcessResponseError(HttpResponseMessage httpResponse, WebPushNotification notification)
        {
            string responseBody = null;

            try
            {
                responseBody = await httpResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
            catch { }

            var msg = $"HTTP Error: Status: {httpResponse.StatusCode}, ReasonPhrase: {httpResponse.ReasonPhrase}";

            throw new WebPushNotificationException(notification, msg, responseBody)
            {
                IsExpiredSubscription = IsExpiredSubscription(httpResponse),
                IsPayloadExceedLimit = IsPayloadExceedLimit(httpResponse, responseBody)
            };
        }

        private bool IsPayloadExceedLimit(HttpResponseMessage response, string responseBody)
        {
            //gcm returns entity too large response
            if (response.StatusCode == HttpStatusCode.RequestEntityTooLarge)
            {
                return true;
            }

            //actual behavior for gcm
            if (responseBody.Contains("data passed in the request must be less than"))
            {
                return true;
            }

            //mozilla push service returns bad gateway response (gateway timeout response was returning earlier)
            if (response.StatusCode == HttpStatusCode.GatewayTimeout || response.StatusCode == HttpStatusCode.BadGateway)
            {
                return true;
            }

            return false;
        }

        private bool IsExpiredSubscription(HttpResponseMessage response)
        {
            //both gcm and mozilla push service send gone response for outdated subscriptions
            if (response.StatusCode == HttpStatusCode.Gone)
            {
                return true;
            }

            //gcm returns such response for invalid subscription
            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                if (response.ReasonPhrase == "UnauthorizedRegistration")
                {
                    return true;
                }
            }

            //firefox push service sends notfound for invalid subscription
            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                return true;
            }

            return false;
        }
    }
}