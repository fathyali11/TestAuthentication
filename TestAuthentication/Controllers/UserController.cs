﻿using Microsoft.AspNetCore.Mvc;
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
    [HttpPut("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        var userId=User.FindFirstValue(ClaimTypes.NameIdentifier);
        var result = await _userService.ChangePasswordAsync(userId!,request, cancellationToken);
        return result.Match<IActionResult>(
            errors => BadRequest(errors),
            success => Ok(),
            error => BadRequest(error)
        );
    }

    [HasPermission(CustomerRoleAndPermissions.CanEditUserProfile)]
    [HttpPut("update-profile")]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request, CancellationToken cancellationToken = default)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var result = await _userService.UpdateProfileAsync(userId!, request, cancellationToken);
        return result.Match<IActionResult>(
            errors => BadRequest(errors),
            success => Ok(),
            error => BadRequest(error)
        );
    }

    [HasPermission(CustomerRoleAndPermissions.CanViewUserProfile)]
    [HttpGet("current-user")]
    public async Task<IActionResult> GetCurrentUser(CancellationToken cancellationToken = default)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var result = await _userService.GetCurrentUserAsync(userId!, cancellationToken);
        return result.Match<IActionResult>(
            userProfile => Ok(userProfile),
            error => BadRequest(error)
        );
    }

    [HasPermission(CustomerRoleAndPermissions.CanEditUserProfile)]
    [HttpPut("update-profile-picture")]
    public async Task<IActionResult> UpdateProfilePicture([FromForm] UpdateProfilePictureRequest request, CancellationToken cancellationToken = default)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var result = await _userService.UpdateProfilePictureAsync(userId!, request, cancellationToken);
        return result.Match<IActionResult>(
            errors => BadRequest(errors),
            success => Ok(),
            error => BadRequest(error)
        );
    }

    [HasPermission(AdminRoleAndPermissions.CanEditUser)]
    [HttpPut("change-status")]
    public async Task<IActionResult> ChangeStatusOfUserAccount(ChangeStatusOfUserAccountRequest request,CancellationToken cancellationToken = default)
    {
        var result = await _userService.ChangeStatusOfUserAccountAsync(request, cancellationToken);
        return result.Match<IActionResult>(
            errors => BadRequest(errors),
            success => Ok(),
            error => BadRequest(error)
        );
    }
    [HasPermission(AdminRoleAndPermissions.CanViewUser)]
    [HttpGet("all-users")]
    public async Task<ActionResult> GetAllUsers(CancellationToken cancellationToken=default)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Ok(await _userService.GetAllUsersAsync(userId!, cancellationToken));
    }

    [HasPermission(AdminRoleAndPermissions.CanEditUser)]
    [HttpPut("add-to-role")]
    public async Task<IActionResult> AddToRole(AddToRoleRequest request, CancellationToken cancellationToken = default)
    {
        var result = await _userService.AddToRoleAsync(request, cancellationToken);
        return result.Match<IActionResult>(
            errors => BadRequest(errors),
            success => Ok(),
            error => BadRequest(error)
        );
    }
}