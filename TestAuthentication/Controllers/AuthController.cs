
using Microsoft.AspNetCore.Mvc;
using TestAuthentication.DTOS;
using TestAuthentication.Services;

namespace TestAuthentication.Controllers;
[Route("api/[controller]")]
[ApiController]
public class AuthController(IAuthServices _authServices) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.RegisterAsync(request, cancellationToken);
        if (!result.IsSuccess)
            return BadRequest(result.Message);
        return Ok(result);
    }
}
