namespace TestAuthentication.Mappings;
public class UserMapping
{
    public static void ConfigMapping()
    {
        TypeAdapterConfig<ApplicationUser, UserData>.NewConfig();
        TypeAdapterConfig<RegisterRequest, ApplicationUser>.NewConfig();
        TypeAdapterConfig<UpdateProfileRequest, ApplicationUser>.NewConfig();
        TypeAdapterConfig<ApplicationUser, CurrentUserProfileResponse>.NewConfig();
    }
}
