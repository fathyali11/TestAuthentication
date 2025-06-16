namespace TestAuthentication.Models;
public class ApplicationUser: IdentityUser
{
    public string Address { get; set; } = string.Empty;
    public string ProfilePictureUrl { get; set; } = string.Empty;
    public bool IsEnable { get; set; } = true;
    public DateTime CreatedAt { get; set; }= DateTime.UtcNow;
}
