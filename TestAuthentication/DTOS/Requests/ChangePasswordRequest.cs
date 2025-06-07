namespace TestAuthentication.DTOS.Requests;

public record ChangePasswordRequest(
    string OldPassword,
    string NewPassword,
    string ConfirmNewPassword
);