namespace TestAuthentication.Constants.AuthoriaztionFilters;

public static class CustomerRoleAndPermissions
{
    public static string Name { get; } = "Customer";
    public static string Type { get; } = "Permission";

    public const string CanViewUserProfile = "CanViewUserProfile";
    public const string CanEditUserProfile = "CanEditUserProfile";
    public const string CanDeleteUserProfile = "CanDeleteUserProfile";
    public const string CanCreateUserProfile = "CanCreateUserProfile";

    public const string CanViewUserProfilePicture = "CanViewUserProfilePicture";
    public const string CanEditUserProfilePicture = "CanEditUserProfilePicture";
    public const string CanDeleteUserProfilePicture = "CanDeleteUserProfilePicture";
    public const string CanCreateUserProfilePicture = "CanCreateUserProfilePicture";

    public static IList<string?> GetAllPermissions() =>
        typeof(CustomerRoleAndPermissions).GetFields().Select(x => x.GetValue(x) as string).ToList();
}