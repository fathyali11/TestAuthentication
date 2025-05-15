using Mapster;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.DTOS.Responses;
using TestAuthentication.Models;

namespace TestAuthentication.Mappings;

public class UserMapping
{
    public static void ConfigMapping()
    {
        TypeAdapterConfig<ApplicationUser, UserData>.NewConfig();
        TypeAdapterConfig<RegisterRequest, ApplicationUser>.NewConfig();
    }
}
