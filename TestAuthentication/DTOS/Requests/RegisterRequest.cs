namespace UsersManagement.DTOS.Requests;

public record RegisterRequest(
    string UserName,
    string Email,
    string Address,
    string Password,
    IFormFile ProfilePicture
);
