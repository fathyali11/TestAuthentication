using FluentValidation;
using TestAuthentication.DTOS.Requests;

namespace TestAuthentication.CustomValidations;

public class ResendEmailConfirmationRequestValidator:AbstractValidator<ResendEmailConfirmationRequest>
{
    public ResendEmailConfirmationRequestValidator()
    {
        RuleFor(x=>x.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress()
            .WithMessage("Invalid email format");
    }
}
