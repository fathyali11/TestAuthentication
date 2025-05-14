namespace TestAuthentication.DTOS.Requests;

public record RegisterRequest(
    string Username,
    string Email,
    string Address,
    string Password
);
