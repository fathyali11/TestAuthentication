namespace TestAuthentication.Constants.AuthoriaztionFilters;

public static class AdminRoleAndPermissions
{
    public static string Name { get; } = "Admin";
    public static string Type { get; } = "Permission";

    // Permissions
    public const string CanCreateUser = "CanCreateUser";
    public const string CanDeleteUser = "CanDeleteUser";
    public const string CanEditUser = "CanEditUser";
    public const string CanViewUser = "CanViewUser";


    public const string CanCreateRole = "CanCreateRole";
    public const string CanDeleteRole = "CanDeleteRole";
    public const string CanEditRole = "CanEditRole";
    public const string CanViewRole = "CanViewRole";


    public const string CanCreatePermission = "CanCreatePermission";
    public const string CanDeletePermission = "CanDeletePermission";
    public const string CanEditPermission = "CanEditPermission";
    public const string CanViewPermission = "CanViewPermission";

    public static IList<string?> GetAllPermissions()=>
        typeof(AdminRoleAndPermissions).GetFields().Select(x=>x.GetValue(x) as string).ToList();
}
