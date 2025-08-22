using EntraApiAuth.Model;

namespace EntraApiAuth.Services
{
    public interface IAuthenticationService
    {
        Task<AuthenticationResponse> AuthenticateWithUsernamePasswordAsync(string username, string password);
        Task<AuthenticationResponse> AuthenticateWithCodeAsync(string code, string redirectUri);
        Task<AuthenticationResponse> RefreshTokenAsync(string refreshToken);
        Task<string> GetAuthorizationUrlAsync(string redirectUri, string state);
        Task<UserInfo?> GetUserInfoAsync(string accessToken);
        Task<bool> ValidateTokenAsync(string token);
        Task RevokeTokenAsync(string token);
    }
}
