using FluentValidation;
using TestAuthentication.DTOS.Requests;

namespace TestAuthentication.CustomValidations;

public class UpdateProfileRequestValidator:AbstractValidator<UpdateProfileRequest>
{
    public UpdateProfileRequestValidator()
    {
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
    }
}