namespace EntraApiAuth.Model;

    public class LoginResponse
    {
        public string AccessToken { get; set; }
        public DateTime ExpiresOn { get; set; }
    }
