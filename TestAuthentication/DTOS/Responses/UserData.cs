namespace TestAuthentication.DTOS.Responses;

public class UserData
{
    public string Id { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public List<string> Roles { get; set; } = default!;
    public List<string> Permissions { get; set; } = default!;
}
