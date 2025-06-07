using TestAuthentication.DTOS.General;
using OneOf;
using TestAuthentication.DTOS.Requests;
namespace TestAuthentication.Services.UserServices;

public interface IUserService
{
    Task<OneOf<List<ValidationError>, bool, Error>> ChangePasswordAsync(string userId, ChangePasswordRequest request, CancellationToken cancellationToken = default);
}
