using FluentValidation;
using TestAuthentication.DTOS.Requests;

namespace TestAuthentication.CustomValidations;

public class ChangeStatusOfUserAccountRequestValidator:AbstractValidator<ChangeStatusOfUserAccountRequest>
{
    public ChangeStatusOfUserAccountRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress()
            .WithMessage("Invalid email format");
    }
}
