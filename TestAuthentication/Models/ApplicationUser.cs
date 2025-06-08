using Microsoft.AspNetCore.Identity;

namespace TestAuthentication.Models;

public class ApplicationUser: IdentityUser
{
    public string Address { get; set; } = string.Empty;
    // add image url for profile picture
    public string ProfilePictureUrl { get; set; } = string.Empty;
}
