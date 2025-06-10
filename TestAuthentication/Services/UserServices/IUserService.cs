using OneOf;
using TestAuthentication.DTOS.General;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.DTOS.Responses;
namespace TestAuthentication.Services.UserServices;

public interface IUserService
{
    Task<OneOf<List<ValidationError>, bool, Error>> ChangePasswordAsync(string userId, ChangePasswordRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>, bool, Error>> UpdateProfileAsync(string userId, UpdateProfileRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<CurrentUserProfileResponse, Error>> GetCurrentUserAsync(string userId, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>, bool, Error>> UpdateProfilePictureAsync(string userId, UpdateProfilePictureRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>, bool, Error>> ChangeStatusOfUserAccountAsync(ChangeStatusOfUserAccountRequest request, CancellationToken cancellationToken = default);
    Task<IEnumerable<AdminUsersProfileResponse>> GetAllUsersAsync(string userId, CancellationToken cancellationToken = default);

}
