using Newtonsoft.Json;
using System;

namespace TokenAuthenticationWEBAPI.Models
{
    // The body of the response from API is a JSON object that 
    // contains the following properties (and a couple of others
    // that we're not capturing).
    public class Token
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        public string Error { get; set; }

        public DateTime ExpiredDateTime { get; set; }
    }
}