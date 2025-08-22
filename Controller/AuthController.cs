using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using System.Security;
using EntraApiAuth.Model;
using EntraApiAuth.Services;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authServices;
    private readonly IConfiguration _config;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IAuthenticationService authService,
        IConfiguration config,
        ILogger<AuthController> logger) {
        this._authServices = authService;
        this._config = config;
        this._logger = logger;
    }

    /// <summary>
    /// Authenticates a user using the Resource Owner Password Credentials (ROPC) flow.
    /// </summary>

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var result = await _authServices.AuthenticateWithUsernamePasswordAsync(request.Username, request.Password);

        if (result.Success)
        {
            this._logger.LogInformation("User {Username} logged in successfully", request.Username);
            return Ok(result);
        }

        this._logger.LogWarning("Failed login attempt for user {Username}", request.Username);
        return Unauthorized(new { Error = result.Error ?? "Invalid credentials" });
    }

    /// <summary>
    /// Get Authorization URL for OAuth 2.0 authorization code flow.
    /// </summary>

    [HttpGet("authorize")]
    [AllowAnonymous]
    public async Task<IActionResult> GetAuthorizeUrl([FromQuery] string redirectUri = null, [FromQuery] string? state = null)
    {
        redirectUri = redirectUri ?? _config["Authentication:RedirectUri"] ?? string.Empty;
        state ??= Guid.NewGuid().ToString();

        var authUrl = await this._authServices.GetAuthorizationUrlAsync(redirectUri, state);
        return Ok(new AuthorizationUrlResponse
        {
            AuthUrl = authUrl,
            State = state
        });
    }

    /// <summary>
    /// Exchanges an authorization code for an access token.
    /// </summary>

    [HttpPost("callback")]
    [AllowAnonymous]
    public async Task<IActionResult> AuthCallback([FromBody] AuthCodeRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (string.IsNullOrEmpty(request.Code) || string.IsNullOrEmpty(request.RedirectUri))
            return BadRequest(new { Error = "Authorization code and redirect URI are required" });

        var result = await this._authServices.AuthenticateWithCodeAsync(request.Code, request.RedirectUri);

        if (result.Success)
        {
            this._logger.LogInformation("Authorization code exchange successful");
            return Ok(result);
        }

        this._logger.LogWarning("Authorization code exchange failed: {Error}", result.Error);
        return Unauthorized(new { Error = result.Error ?? "Invalid authorization code" });
    }

    /// <summary>
    /// Refresh Access Token
    /// </summary>
    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);
        if (string.IsNullOrEmpty(request.RefreshToken))
            return BadRequest(new { Error = "Refresh token is required" });
        var result = await this._authServices.RefreshTokenAsync(request.RefreshToken);
        if (result.Success)
        {
            this._logger.LogInformation("Token refreshed successfully");
            return Ok(result);
        }
        this._logger.LogWarning("Token refresh failed: {Error}", result.Error);
        return Unauthorized(new { Error = result.Error ?? "Invalid refresh token" });
    }

    /// <summary>
    /// Logout User
    /// </summary>

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout()
    {
        var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase);

        if (!string.IsNullOrEmpty(token))
            await this._authServices.RevokeTokenAsync(token);

        var logoutUrl = $"{this._config["AzureAd:Instance"]}/{this._config["AzureAd:TenantId"]}/{this._config["AzureAd:DraftUrl:Logout"]}";
        return Ok(new
        {
            message = "Logged out successful",
            logoutUrl = logoutUrl
        });
    }

    /// <summary>
    /// Validate Token
    /// </summary>
    [HttpPost("validate")]
    [AllowAnonymous]
    public async Task<IActionResult> ValidateToken([FromBody] string token)
    {
        try
        {

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { Error = "Token is required" });

            var isValid = await this._authServices.ValidateTokenAsync(token);
            this._logger.LogInformation("Token validation successful");
            return Ok(new { valid = isValid });
        }
        catch (Exception ex)
        {
            this._logger.LogWarning("Token validation failed: {Error}", ex.InnerException?.Message);
            return Unauthorized(new { Error = ex.Message ?? "Invalid token" });
        }
    }


    /// <summary>
    /// Get current user information
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase);

        var userInfo = await this._authServices.GetUserInfoAsync(token);

        if (userInfo != null)
            return Ok(userInfo);

        return NotFound(new { Error = "User information not found" });
    }





}
