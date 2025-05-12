using TestAuthentication.DTOS;

namespace TestAuthentication.Services;

public interface IAuthServices
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request,CancellationToken cancellationToken=default);
    Task<AuthResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);
}
