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
        TypeAdapterConfig<RegisterRequest, ApplicationUser>.NewConfig()
            .Map(dest => dest.ProfilePictureUrl, src => src.ProfilePicture.FileName.Replace(" ",""));
        TypeAdapterConfig<UpdateProfileRequest, ApplicationUser>.NewConfig();
        TypeAdapterConfig<ApplicationUser, CurrentUserProfileResponse>.NewConfig();
    }
}
