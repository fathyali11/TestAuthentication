using TestAuthentication.DTOS.General;

namespace TestAuthentication.Constants.Errors;

public static class UserError
{
    public static readonly Error UserNotFound = new("UserNotFound", "User not found", 404);
    public static readonly Error UserAlreadyExists = new("UserAlreadyExists", "User already exists", 409);
    public static readonly Error InvalidPassword = new("InvalidPassword", "Invalid password", 401);
    public static readonly Error InvalidEmail = new("InvalidEmail", "Invalid email", 400);
    public static readonly Error InvalidToken = new("InvalidToken", "Invalid token", 401);
    public static readonly Error TokenExpired = new("TokenExpired", "Token expired", 401);
    public static readonly Error ServerError = new("ServerError", "Internal server error", StatusCodes.Status500InternalServerError);
    public static readonly Error NotConfirmed = new("NotConfirmed", "Email not confirmed", StatusCodes.Status401Unauthorized);
    public static readonly Error NotActive = new("NotActive", "User is not enable", StatusCodes.Status401Unauthorized);

}
