namespace TestAuthentication.DTOS;

public record LoginRequest(
    string Username,
    string Password
);
