using Microsoft.AspNetCore.Mvc;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.Services.AuthService;

namespace TestAuthentication.Controllers;
[Route("api/[controller]")]
[ApiController]
public class AuthController(IAuthServices _authServices) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromForm] RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.RegisterAsync(request, cancellationToken);
        if (result.IsT0)
            return BadRequest(result.AsT0);
        else if (result.IsT1)
            return BadRequest(result.AsT1);
        return Ok(result.AsT2);
    }
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.LoginAsync(request, cancellationToken);
        if (result.IsT0)
            return BadRequest(result.AsT0);
        else if (result.IsT1)
            return Ok(result.AsT1);
        return BadRequest(result.AsT2);
    }
    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] ConfirmEmailRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ConfirmEmailAsync(request, cancellationToken);
        if(result.IsT0)
            return BadRequest(result.AsT0);
        else if (result.IsT1)
            return Ok(result.AsT1);
        else if(result.IsT2)
            return BadRequest(result.AsT2);
        return Ok(result.AsT3);

    }
    [HttpPost("resend-email-confirmation")]
    public async Task<IActionResult> ResendEmailConfirmation([FromBody] ResendEmailConfirmationRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ResendEmailConfirmationAsync(request, cancellationToken);
        if (result.IsT0)
            return BadRequest(result.AsT0);
        else if (result.IsT1)
            return Ok(result.AsT1);
        else
            return BadRequest(result.AsT2);
    }
    [HttpPost("forget-password")]
    public async Task<IActionResult> ForgetPassword([FromBody] ForgetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ForgetPasswordAsync(request, cancellationToken);
        if(result.IsT0)
            return BadRequest(result.AsT0);
        else if (result.IsT1)
            return Ok(result.AsT1);
        else
            return BadRequest(result.AsT2);
    }
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.ResetPasswordAsync(request, cancellationToken);
        if(result.IsT0)
            return BadRequest(result.AsT0);
        else if (result.IsT1)
            return Ok(result.AsT1);
        else
            return BadRequest(result.AsT2);
    }
    [HttpPost("add-to-role")]
    public async Task<IActionResult> AddToRole([FromBody] AddToRoleRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _authServices.AddToRoleAsync(request, cancellationToken);
        if (result.IsT0)
            return BadRequest(result.AsT0);
        else if (result.IsT1)
            return Ok(result.AsT1);
        else
            return BadRequest(result.AsT2);
    }
}
