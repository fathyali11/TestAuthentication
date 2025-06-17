namespace UsersManagement.DTOS.Responses;

public class AdminUsersProfileResponse
{
    public string UserName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string ProfilePictureUrl { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public string Address { get; set; } = string.Empty;
    public string Role { get; set; } = default!;

    public DateTime CreatedAt { get; set; }
    //public DateTime LastLoginAt { get; set; }
}
