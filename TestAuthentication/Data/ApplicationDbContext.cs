using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace TestAuthentication.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options):IdentityDbContext(options)
{

}
