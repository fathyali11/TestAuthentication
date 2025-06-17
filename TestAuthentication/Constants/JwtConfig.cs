namespace UsersManagement.Constants;

public class JwtConfig
{
    public string Key { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpireTime { get; set; } 
    public int RefreshExpireTime { get; set; }
}
