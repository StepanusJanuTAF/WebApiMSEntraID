using EntraApiAuth.Model;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;

namespace EntraApiAuth.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IConfidentialClientApplication _app;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IMemoryCache _memoryCache;
        private readonly ILogger<AuthenticationService> _logger;
        private readonly string[] _scopes;
        private readonly string _authority;
        private readonly string _tenantId;

        public AuthenticationService(
            IConfidentialClientApplication app,
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory,
            IMemoryCache cache,
            ILogger<AuthenticationService> logger)
        {
            _app = app;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _memoryCache = cache;
            _logger = logger;
            _tenantId = _configuration["AzureAd:TenantId"] ?? throw new ArgumentNullException("TenantId");
            _authority = $"{_configuration["AzureAd:Instance"]}/{_tenantId}";
            _scopes = _configuration.GetSection("AzureAd:Scopes").Get<string[]>() ?? new[] { "User.Read" };
        }

        public async Task<AuthenticationResponse> AuthenticateWithUsernamePasswordAsync(string username, string password)
        {
            try
            {
                var application = PublicClientApplicationBuilder
                    .Create(_configuration["AzureAd:ClientId"])
                    .WithAuthority($"{_configuration["AzureAd:Instance"]}/{_configuration["AzureAd:TenantId"]}")
                    .Build();

                var scopes = new string[]
                    { $"{_configuration["AzureAd:GraphMS:Uri"]}/{_configuration["AzureAd:GraphMS:DefaultScope"]}" };

                // Note: ROPC flow is not recommended for production use
                // Consider using Authorization Code flow instead
                var result = await application.AcquireTokenByUsernamePassword(
                        _scopes,
                        username,
                        password)
                    .ExecuteAsync();

                return await CreateAuthenticationResponse(result);
            }
            catch (MsalException ex)
            {
                _logger.LogError(ex, "Authentication failed for user {Username}", username);
                return new AuthenticationResponse
                {
                    Success = false,
                    Error = GetUserFriendlyError(ex)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during authentication");
                return new AuthenticationResponse
                {
                    Success = false,
                    Error = "An unexpected error occurred during authentication"
                };
            }
        }

        public async Task<AuthenticationResponse> AuthenticateWithCodeAsync(string code, string redirectUri)
        {
            try
            {
                var application = ConfidentialClientApplicationBuilder
                    .Create(_configuration["AzureAd:ClientId"])
                    .WithClientSecret(_configuration["AzureAd:ClientSecret"])
                    .WithAuthority(AzureCloudInstance.AzurePublic, _configuration["AzureAd:TenantId"])
                    .WithRedirectUri(redirectUri)
                    .Build();

                var result = await application.AcquireTokenByAuthorizationCode(
                        _scopes,
                        code)
                    .ExecuteAsync();

                return await CreateAuthenticationResponse(result);
            }
            catch (MsalException ex)
            {
                _logger.LogError(ex, "Failed to exchange authorization code for token");
                return new AuthenticationResponse
                {
                    Success = false,
                    Error = GetUserFriendlyError(ex)
                };
            }
        }

        public async Task<AuthenticationResponse> RefreshTokenAsync(string refreshToken)
        {
            try
            {
                // Try to get the account from cache
                var accounts = await _app.GetAccountsAsync();
                var account = accounts.FirstOrDefault();

                if (account == null)
                {
                    return new AuthenticationResponse
                    {
                        Success = false,
                        Error = "No cached account found"
                    };
                }

                var result = await _app.AcquireTokenSilent(_scopes, account)
                    .ExecuteAsync();

                return await CreateAuthenticationResponse(result);
            }
            catch (MsalException ex)
            {
                _logger.LogError(ex, "Failed to refresh token");
                return new AuthenticationResponse
                {
                    Success = false,
                    Error = "Failed to refresh token. Please login again."
                };
            }
        }

        public async Task<string> GetAuthorizationUrlAsync(string redirectUri, string state)
        {
            var authUrl = await _app.GetAuthorizationRequestUrl(_scopes)
                .WithRedirectUri(redirectUri)
                .ExecuteAsync();

            return QueryHelpers.AddQueryString(authUrl.ToString(), "state", state);
        }

        public async Task<UserInfo?> GetUserInfoAsync(string accessToken)
        {
            try
            {
                var httpClient = _httpClientFactory.CreateClient();
                httpClient.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", accessToken);

                var response = await httpClient.GetAsync($"{_configuration["AzureAd:GraphMS:Uri"]}/v1.0/me");

                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var graphUser = JsonSerializer.Deserialize<GraphUser>(json);

                    return new UserInfo
                    {
                        Id = graphUser?.Id ?? "",
                        Email = graphUser?.Mail ?? graphUser?.UserPrincipalName ?? "",
                        DisplayName = graphUser?.DisplayName ?? "",
                        GivenName = graphUser?.GivenName ?? "",
                        Surname = graphUser?.Surname ?? ""
                    };
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get user info from Graph API");
                return null;
            }
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            try
            {
                var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    $"{_authority}/v2.0/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever());

                var config = await configManager.GetConfigurationAsync();
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuers = new[] { $"{_authority}/v2.0", $"https://sts.windows.net/{_tenantId}/" },
                    ValidateAudience = true,
                    ValidAudience = _configuration["AzureAd:ClientId"],
                    ValidateLifetime = true,
                    IssuerSigningKeys = config.SigningKeys,
                    ValidateIssuerSigningKey = true
                };

                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(token, validationParameters, out _);

                return principal != null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Token validation failed");
                return false;
            }
        }

        public async Task RevokeTokenAsync(string token)
        {
            // Microsoft doesn't support token revocation directly
            // You would typically clear the token cache
            var accounts = await _app.GetAccountsAsync();
            foreach (var account in accounts)
            {
                await _app.RemoveAsync(account);
            }
        }

        private async Task<AuthenticationResponse> CreateAuthenticationResponse(AuthenticationResult result)
        {
            var userInfo = await GetUserInfoAsync(result.AccessToken);

            return new AuthenticationResponse
            {
                Success = true,
                AccessToken = result.AccessToken,
                IdToken = result.IdToken,
                ExpiresIn = (int)(result.ExpiresOn - DateTimeOffset.UtcNow).TotalSeconds,
                User = userInfo ?? ExtractUserInfoFromToken(result.IdToken)
            };
        }

        private UserInfo ExtractUserInfoFromToken(string idToken)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadJwtToken(idToken);

                return new UserInfo
                {
                    Id = jsonToken.Claims.FirstOrDefault(c => c.Type == "oid")?.Value ?? "",
                    Email = jsonToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value
                           ?? jsonToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value ?? "",
                    DisplayName = jsonToken.Claims.FirstOrDefault(c => c.Type == "name")?.Value ?? "",
                    GivenName = jsonToken.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value ?? "",
                    Surname = jsonToken.Claims.FirstOrDefault(c => c.Type == "family_name")?.Value ?? "",
                    Roles = jsonToken.Claims.Where(c => c.Type == "roles").Select(c => c.Value).ToList()
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to extract user info from token");
                return new UserInfo();
            }
        }

        private string GetUserFriendlyError(MsalException ex)
        {
            return ex.ErrorCode switch
            {
                "invalid_grant" => "Invalid username or password",
                "invalid_request" => "Invalid request format",
                "unauthorized_client" => "Client is not authorized for this operation",
                "consent_required" => "User consent is required",
                "interaction_required" => "User interaction is required",
                _ => "Authentication failed. Please try again."
            };
        }
    }
}
