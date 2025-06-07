using FluentValidation;
using Microsoft.AspNetCore.Identity;
using OneOf;
using TestAuthentication.Constants.Errors;
using TestAuthentication.CustomValidations;
using TestAuthentication.DTOS.General;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.Models;
using TestAuthentication.Services.General;

namespace TestAuthentication.Services.UserServices;

public class UserService(IValidator<ChangePasswordRequest> _changePasswordRequestValidator,
    UserManager<ApplicationUser> _userManager,
    ILogger<UserService> _logger,
    ValidationService _validationService):IUserService
{
    public async Task<OneOf<List<ValidationError>, bool, Error>> ChangePasswordAsync(string userId,ChangePasswordRequest request,CancellationToken cancellationToken=default)
    {
        _logger.LogInformation("Validation request with password {Password} and new password {NewPassword} and confirm password {ConfirmPassword}", request.OldPassword,request.NewPassword,request.ConfirmNewPassword);

        var validationResult = await _validationService.ValidateRequest(_changePasswordRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for change password: {Errors}", validationResult);
            return validationResult;
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("User with ID {UserId} not found", userId);
            return  UserError.UserNotFound;
        }
        var result = await _userManager.ChangePasswordAsync(user, request.OldPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Failed to change password for user with ID {UserId}: {Errors}", userId, result.Errors);
            return UserError.ServerError;
        }
        _logger.LogInformation("Password changed successfully for user with ID {UserId} and email {Email}", userId,user.Email);
        return true;
    }
}
