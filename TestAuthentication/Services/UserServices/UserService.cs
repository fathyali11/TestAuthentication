using FluentValidation;
using Mapster;
using MapsterMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Hybrid;
using OneOf;
using System.Threading;
using TestAuthentication.Constants.Errors;
using TestAuthentication.CustomValidations;
using TestAuthentication.Data;
using TestAuthentication.DTOS.General;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.DTOS.Responses;
using TestAuthentication.Models;
using TestAuthentication.Services.BlobStorage;
using TestAuthentication.Services.General;

namespace TestAuthentication.Services.UserServices;

public class UserService(IValidator<ChangePasswordRequest> _changePasswordRequestValidator,
    IValidator<ChangeStatusOfUserAccountRequest> _changeStatusOfUserAccountRequestValidator,
    IValidator<AddToRoleRequest> _addToRoleRequestValidator,
    UserManager<ApplicationUser> _userManager,
    ILogger<UserService> _logger,
    IValidator<UpdateProfileRequest> _updateProfileRequestValidator,
    ValidationService _validationService,IMapper _mapper,
    IValidator<UpdateProfilePictureRequest> _updateProfilePictureRequest,
    BlobStorageServices _blobStorageServices,
    ApplicationDbContext _context,HybridCache _hybridCache) :IUserService
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

    public async Task<OneOf<List<ValidationError>, bool, Error>> UpdateProfileAsync(string userId, UpdateProfileRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Updating profile for user with ID {UserId}", userId);
        var validationResult = await _validationService.ValidateRequest(_updateProfileRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for update profile: {Errors}", validationResult);
            return validationResult;
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} not found", userId);
            return UserError.UserNotFound;
        }
        _mapper.Map(request, user);
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Failed to update profile for user with ID {UserId}: {Errors}", userId, result.Errors);
            return UserError.ServerError;
        }
        await _hybridCache.RemoveAsync("AllUsers", cancellationToken);
        _logger.LogInformation("Profile updated successfully for user with ID {UserId} and email {Email}", userId, user.Email);
        return true;
    }

    public async Task<OneOf<CurrentUserProfileResponse, Error>> GetCurrentUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Retrieving current user with ID {UserId}", userId);
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} not found", userId);
            return UserError.UserNotFound;
        }
        _logger.LogInformation("Current user retrieved successfully with ID {UserId} and email {Email}", userId, user.Email);


        var response= _mapper.Map<CurrentUserProfileResponse>(user);
        response.ProfilePictureUrl = await _blobStorageServices.GetFileUrlAsync(user.ProfilePictureUrl);
        return response;
    }
    public async Task<OneOf<List<ValidationError>, bool, Error>> UpdateProfilePictureAsync(string userId, UpdateProfilePictureRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Updating profile picture for user with ID {UserId}", userId);
        var validationResult = await _validationService.ValidateRequest(_updateProfilePictureRequest, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for update profile picture: {Errors}", validationResult);
            return validationResult;
        }
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            _logger.LogWarning("User with ID {UserId} not found", userId);
            return UserError.UserNotFound;
        }
        var oldProfilePictureUrl = user.ProfilePictureUrl;
        await _blobStorageServices.UpdateFileAsync(request.ProfilePicture, user.ProfilePictureUrl);
        user.ProfilePictureUrl = request.ProfilePicture.FileName.Replace(" ", "");

        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Failed to update profile picture for user with ID {UserId}: {Errors}", userId, result.Errors);
            return UserError.ServerError;
        }
        await _hybridCache.RemoveAsync($"UserProfile_{oldProfilePictureUrl}", cancellationToken);
        _logger.LogInformation("Profile picture updated successfully for user with ID {UserId}", userId);
        return true;
    }
    public async Task<OneOf<List<ValidationError>,bool, Error>> ChangeStatusOfUserAccountAsync(ChangeStatusOfUserAccountRequest request, CancellationToken cancellationToken = default)
    {
        var validationResult = await _validationService.ValidateRequest(_changeStatusOfUserAccountRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for change status of user account: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Change status of user account with Email {Email}", request.Email);
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            _logger.LogWarning("User with Email {Email} not found", request.Email);
            return UserError.UserNotFound;
        }

        user.IsEnable = !user.IsEnable;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            _logger.LogWarning("Failed to change status of user account with Email {Email}: {Errors}", request.Email, result.Errors);
            return UserError.ServerError;
        }
        await _hybridCache.RemoveAsync("AllUsers", cancellationToken);
        _logger.LogInformation("User account with Email {Email} disabled successfully", request.Email);
        return true;
    }
    public async Task<IEnumerable<AdminUsersProfileResponse>> GetAllUsersAsync(string userId,CancellationToken cancellationToken = default)
    {
        var cachUsersKey=$"AllUsers";

        var cachedUsers = await _hybridCache.GetOrCreateAsync(cachUsersKey, async _ =>
        {
            return await GetAllCachedUsers(userId, cancellationToken);
        }, cancellationToken: cancellationToken);

            var response=await Task.WhenAll(cachedUsers.Select(async user=>
            {
                var cacheKey = $"UserProfile_{user.ProfilePictureUrl}";

                var pictureUrl = await _hybridCache.GetOrCreateAsync(cacheKey,
                    async _ =>
                    {
                       var url = await _blobStorageServices.GetFileUrlAsync(user.ProfilePictureUrl);
                        return url;
                    },cancellationToken:cancellationToken);


                return new AdminUsersProfileResponse
                {
                    UserName = user.UserName,
                    Email = user.Email,
                    ProfilePictureUrl = pictureUrl,
                    IsActive = user.IsActive,
                    Address = user.Address,
                    CreatedAt = user.CreatedAt,
                    Role = user.Role
                };
                
            }));
        return response;
    }

    public async Task<OneOf<List<ValidationError>, bool, Error>> AddToRoleAsync(AddToRoleRequest request,CancellationToken cancellationToken=default)
    {
        var validationResult = await _validationService.ValidateRequest(_addToRoleRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for change status of user account: {Errors}", validationResult);
            return validationResult;
        }

        var user = await _userManager.FindByEmailAsync(request.Email);
        if(user is null)
        {
            _logger.LogWarning("User with Email {Email} not found", request.Email);
            return UserError.UserNotFound;
        }
        var roles = await _userManager.GetRolesAsync(user);
        var roleName = roles.FirstOrDefault();
        if (string.Equals(roleName, request.RoleName, StringComparison.OrdinalIgnoreCase))
            return true;
        var removeFromRoleResult=await _userManager.RemoveFromRoleAsync(user, roleName!);
        if (!removeFromRoleResult.Succeeded)
        {
            _logger.LogError("cann't remove user with email {Email} from role with name {RoleName}", request.Email, roleName);
            return UserError.ServerError;
        }
        var addToRoleResult = await _userManager.AddToRoleAsync(user, request.RoleName);
        if(!addToRoleResult.Succeeded)
        {
            _logger.LogError("cann't add user with email {Email} to role with name {RoleName}", request.Email, request.RoleName);
            return UserError.ServerError;
        }

        // add logs successful
        _logger.LogInformation("add user with email {Email} to role with name {RoleName} succesfully", request.Email, request.RoleName);
        return true;
    }

    private async Task<IEnumerable<AdminUsersProfileResponse>> GetAllCachedUsers(string userId,CancellationToken cancellationToken=default)
    {
        _logger.LogInformation("Retrieving all users except the current user");
        var data = await (from user in _context.Users.AsNoTracking()
                          join userRole in _context.UserRoles.AsNoTracking() on user.Id equals userRole.UserId
                          join role in _context.Roles.AsNoTracking() on userRole.RoleId equals role.Id
                          where user.Id != userId
                          select new AdminUsersProfileResponse
                          {
                              UserName = user.UserName!,
                              Email = user.Email!,
                              ProfilePictureUrl = user.ProfilePictureUrl,
                              Address = user.Address,
                              IsActive = user.IsEnable,
                              CreatedAt = user.CreatedAt,
                              Role = role.Name!
                          }
                           ).ToListAsync(cancellationToken);
        return data;
    }





}

