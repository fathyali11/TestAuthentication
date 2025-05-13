
using Microsoft.AspNetCore.Mvc;
using TestAuthentication.DTOS;
using TestAuthentication.Services.AuthService;

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
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.LoginAsync(request, cancellationToken);
        if (!result.IsSuccess)
            return BadRequest(result.Message);
        return Ok(result);
    }
    [HttpPost("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] ConfirmEmailRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ConfirmEmailAsync(request, cancellationToken);
        if (!result.IsSuccess)
            return BadRequest(result.Message);
        return Ok(result);
    }
    [HttpPost("resend-email-confirmation")]
    public async Task<IActionResult> ResendEmailConfirmation([FromBody] string email, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ResendEmailConfirmationAsync(email, cancellationToken);
        if (!result.IsSuccess)
            return BadRequest(result.Message);
        return Ok(result);
    }
    [HttpPost("forget-password")]
    public async Task<IActionResult> ForgetPassword([FromBody] string email, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ForgetPasswordAsync(email, cancellationToken);
        if (!result.IsSuccess)
            return BadRequest(result.Message);
        return Ok(result);
    }
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromQuery]string userId, [FromQuery]string token, [FromBody]string newPassword, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ResetPasswordAsync(userId,token,newPassword, cancellationToken);
        if (!result.IsSuccess)
            return BadRequest(result.Message);
        return Ok(result);
    }
}
