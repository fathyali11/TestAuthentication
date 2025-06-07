using FluentValidation;
using TestAuthentication.DTOS.Requests;

namespace TestAuthentication.CustomValidations;

public class ChangePasswordRequestValidator:AbstractValidator<ChangePasswordRequest>
{
    public ChangePasswordRequestValidator()
    {
        RuleFor(x => x.OldPassword)
             .NotEmpty()
             .WithMessage("Password is required")
             .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{6,}$")
             .WithMessage("Password must be at least 6 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.")
             .NotEqual(x => x.NewPassword)
             .WithMessage("New password must be different from old password.");

        RuleFor(x => x.NewPassword)
             .NotEmpty()
             .WithMessage("Password is required")
             .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{6,}$")
             .WithMessage("Password must be at least 6 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.");

        RuleFor(x => x.ConfirmNewPassword)
             .NotEmpty()
             .WithMessage("Password is required")
             .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{6,}$")
             .WithMessage("Password must be at least 6 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.")
             .Equal(x => x.NewPassword)
             .WithMessage("New password and confirm password do not match.");
    }
}
