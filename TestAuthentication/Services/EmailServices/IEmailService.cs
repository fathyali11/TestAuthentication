namespace UsersManagement.Services.EmailServices;

public interface IEmailService
{
    Task SendEmailAsync(string to ,string subject, string body);
}
