namespace PushSharp.Web
{
    public class WebPushConfiguration
    {
        public WebPushConfiguration()
        {
            GcmEndPoint = "https://android.googleapis.com/gcm/send";
        }

        public string GcmAPIKey { get; set; }

        // The VAPID private key as a base64 encoded string
        public string PrivateApplicationKey { get; set; }

        // The VAPID public key as a base64 encoded string
        public string PublicApplicationKey { get; set; }
        
        // Should be a URL or a 'mailto:' email address
        public string Subject { get; set; }

        internal string GcmEndPoint { get; set; }
    }
}