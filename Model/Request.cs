namespace EntraApiAuth.Model
{

    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class AuthCodeRequest
    {
        public string Code { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
    }

    public class  RefreshTokenRequest
    {
        public string RefreshToken { get; set; } = string.Empty;
    }
}


