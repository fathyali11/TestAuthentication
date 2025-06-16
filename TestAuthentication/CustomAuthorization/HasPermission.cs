namespace TestAuthentication.CustomAuthorization;
public class HasPermission(string permission) : AuthorizeAttribute, IAuthorizationFilter
{
    private readonly string _permission = permission;
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        if (string.IsNullOrWhiteSpace(_permission))
        {
            context.Result = new BadRequestObjectResult("Permission cannot be null or empty.");
            return;
        }

        

        if (context.HttpContext.User.Identity is not { IsAuthenticated: true })
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (!context.HttpContext.User.HasClaim(c => c.Type == AdminRoleAndPermissions.Type && c.Value == _permission))
        {
            context.Result = new ForbidResult();
            return;
        }
    }
}
