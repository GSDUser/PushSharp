namespace PushSharp.Web
{
    public class WebPushConfiguration
    {
        public WebPushConfiguration()
        {
            GcmEndPoints = new [] {
                "https://android.googleapis.com/gcm/send",
                "https://fcm.googleapis.com/fcm/send"
            };
        }

        public string GcmAPIKey { get; set; }

        internal string[] GcmEndPoints { get; set; }
    }
}