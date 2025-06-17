namespace UsersManagement.DTOS.Responses;

public class CurrentUserProfileResponse
{
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string ProfilePictureUrl { get; set; } = string.Empty;
}
