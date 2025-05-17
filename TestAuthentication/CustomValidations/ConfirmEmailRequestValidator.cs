using FluentValidation;
using TestAuthentication.DTOS.Requests;

namespace TestAuthentication.CustomValidations;

public class ConfirmEmailRequestValidator : AbstractValidator<ConfirmEmailRequest>
{
    public ConfirmEmailRequestValidator()
    {
        RuleFor(x => x.Token)
            .NotEmpty()
            .WithMessage("Token is required")
            .MinimumLength(10)
            .WithMessage("Token must be at least 10 characters long");
        RuleFor(x => x.UserId)
            .NotEmpty()
            .WithMessage("UserId is required")
            .MinimumLength(10)
            .WithMessage("UserId must be at least 10 characters long");
    }
}
