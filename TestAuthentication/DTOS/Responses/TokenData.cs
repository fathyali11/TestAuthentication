namespace TestAuthentication.DTOS.Responses;

public class TokenData
{
    public string AccessToken { get; set; } = string.Empty;
    public int AccessTokenExpiresIn { get; set; }
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime RefreshTokenExpiresIn { get; set; }
}
