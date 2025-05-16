using FluentValidation;
using TestAuthentication.DTOS.Requests;

namespace TestAuthentication.CustomValidations;

public class RegisterRequestValidator:AbstractValidator<RegisterRequest>
{
    public RegisterRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress()
            .WithMessage("Invalid email format");
        RuleFor(x => x.UserName)
            .NotEmpty()
            .WithMessage("UserName is required")
            .MinimumLength(3)
            .WithMessage("UserName must be at least 3 characters long");
        RuleFor(x => x.Address)
            .NotEmpty()
            .WithMessage("Address is required")
            .MinimumLength(2)
            .WithMessage("Address must be at least 2 characters long");
        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage("Password is required")
            .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{6,}$")
            .WithMessage("Password must be at least 6 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.");

    }
}
