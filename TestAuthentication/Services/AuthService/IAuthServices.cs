using TestAuthentication.DTOS.Requests;
using TestAuthentication.DTOS.Responses;

namespace TestAuthentication.Services.AuthService;

public interface IAuthServices
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);
    Task<AuthResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);
    Task<AuthResponse> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default);
    Task<AuthResponse> ResendEmailConfirmationAsync(string email, CancellationToken cancellationToken = default);
    Task<AuthResponse> ForgetPasswordAsync(string email, CancellationToken cancellationToken = default);
    Task<AuthResponse> ResetPasswordAsync(string userId, string token, string newPassword, CancellationToken cancellationToken = default);
}
