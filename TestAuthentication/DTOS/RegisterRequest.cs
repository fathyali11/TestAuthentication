namespace TestAuthentication.DTOS;

public record RegisterRequest(
    string Username,
    string Email,
    string Address,
    string Password
);
