using Microsoft.AspNetCore.Identity;

namespace TestAuthentication.Models;

public class ApplicationUser: IdentityUser
{
    public string Address { get; set; } = string.Empty;
}
