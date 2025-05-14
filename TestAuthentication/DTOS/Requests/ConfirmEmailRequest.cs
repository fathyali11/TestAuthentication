namespace TestAuthentication.DTOS.Requests;

public record ConfirmEmailRequest(string UserId, string Token);
