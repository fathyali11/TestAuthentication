namespace TestAuthentication.Constants.AuthoriaztionFilters;

public static class CustomerRoleAndPermissions
{
    public static string Name { get; } = "Customer";
    public static string Type { get; } = "Permission";

    public static IList<string?> GetAllPermissions() =>
        typeof(CustomerRoleAndPermissions).GetFields().Select(x => x.GetValue(x) as string).ToList();
}