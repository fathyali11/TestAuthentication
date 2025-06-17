namespace UsersManagement.DTOS.Requests;

public record ResetPasswordRequest(
    string UserId,
    string Token,
    string NewPassword
);
