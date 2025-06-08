namespace TestAuthentication.DTOS.Responses;

public class UserData
{
    public string Id { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string ProfilePictureUrl { get; set; } = string.Empty;
    public string Role { get; set; } = default!;
    public List<string> Permissions { get; set; } = default!;
}
