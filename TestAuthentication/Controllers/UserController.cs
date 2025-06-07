using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using TestAuthentication.Constants.AuthoriaztionFilters;
using TestAuthentication.CustomAuthorization;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.Services.UserServices;

namespace TestAuthentication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController(IUserService _userService) : ControllerBase
{

    [HasPermission(CustomerRoleAndPermissions.CanEditUserProfile)]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        var userId=User.FindFirstValue(ClaimTypes.NameIdentifier);
        var result = await _userService.ChangePasswordAsync(userId!,request, cancellationToken);
        return result.Match<IActionResult>(
            success => Ok(new { Message = "Password changed successfully" }),
            errors => BadRequest(errors),
            error => StatusCode(500, error)
        );
    }
}