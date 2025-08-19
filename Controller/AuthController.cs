using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using System.Security;
using EntraApiAuth.Model;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config) => _config = config;
    [HttpPost("login-ropc")]
    public async Task<IActionResult> LoginROPC([FromBody] LoginRequest request)
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            return BadRequest("Username and password required");

        var securePwd = new SecureString();
        foreach (var c in request.Password) securePwd.AppendChar(c);

        try
        {
            if (string.IsNullOrEmpty(_config["AzureAd:ClientId"]) ||
                string.IsNullOrEmpty(_config["AzureAd:TenantId"]) ||
                string.IsNullOrEmpty(_config["AzureAd:Audience"]))
                throw new Exception("AzureAd configuration missing");

            var app = PublicClientApplicationBuilder.Create(_config["AzureAd:ClientId"])
                .WithAuthority($"{_config["AzureAd:Instance"]}{_config["AzureAd:TenantId"]}")
                .Build();

            var scopes = new[] { $"{_config["AzureAd:Audience"]}/.default" };

            var result = await app.AcquireTokenByUsernamePassword(scopes, request.Username, securePwd).ExecuteAsync();

            return Ok(new LoginResponse
            {
                AccessToken = result.AccessToken,
                ExpiresOn = result.ExpiresOn.UtcDateTime
            });
        }
        catch (MsalUiRequiredException ex)
        {
            return Unauthorized(new
            {
                Message = "Interactive login required or MFA enforced",
                Error = ex.Message
            });
        }
        catch (MsalServiceException ex)
        {
            return Unauthorized(new
            {
                Message = $"Service error: {ex.ErrorCode} - {ex.Message}"
            });
        }
        catch (Exception ex)
        {
            return Unauthorized($"Login failed: {ex.Message}");
        }
    }
}
