namespace TestAuthentication.DTOS.Responses;

public class AuthResponse
{
    public UserData User { get; set; } = default!;
    public TokenData Token { get; set; } = default!;
}
