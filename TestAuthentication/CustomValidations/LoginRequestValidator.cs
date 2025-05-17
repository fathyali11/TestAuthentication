using FluentValidation;
using TestAuthentication.DTOS.Requests;

namespace TestAuthentication.CustomValidations;

public class LoginRequestValidator: AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty()
            .WithMessage("UserName is required")
            .MinimumLength(3)
            .WithMessage("UserName must be at least 3 characters long");
        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage("Password is required")
            .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{6,}$")
            .WithMessage("Password must be at least 6 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.");
    }
}

