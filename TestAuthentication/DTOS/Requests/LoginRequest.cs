namespace UsersManagement.DTOS.Requests;

public record LoginRequest(
    string Username,
    string Password
);
