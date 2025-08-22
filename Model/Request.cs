using System.ComponentModel.DataAnnotations;

namespace EntraApiAuth.Model
{

    public class LoginRequest
    {
        [Required(ErrorMessage = "Username is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [RegularExpression(@"^[^@\s]+@taf\.co\.id$", ErrorMessage = "Only taf.co.id emails are allowed")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long")]
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


