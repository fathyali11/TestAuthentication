namespace TestAuthentication.DTOS;

public record ConfirmEmailRequest(string UserId, string Token);
