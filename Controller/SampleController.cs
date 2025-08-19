using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EntraApiAuth.Controller;

[ApiController]
[Route("api/[controller]")]
public class SampleController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult Public() => Ok("This endpoint is public and requires no authentication.");

    [HttpGet("secure")]
    [Authorize] // Token must be valid
    public IActionResult Secure()
    {
        var userName = User.Identity?.Name ?? "Unknown";
        var userId = User.FindFirst("oid")?.Value ?? "No OID";

        return Ok(new
        {
            Message = $"Hello {userName}, your token is valid!",
            ObjectId = userId
        });
    }
}
