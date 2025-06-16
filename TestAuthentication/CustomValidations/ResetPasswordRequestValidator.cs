namespace TestAuthentication.CustomValidations;
public class ResetPasswordRequestValidator: AbstractValidator<ResetPasswordRequest>
{
    public ResetPasswordRequestValidator()
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
        RuleFor(x => x.NewPassword)
             .NotEmpty()
             .WithMessage("Password is required")
             .Matches(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{6,}$")
             .WithMessage("Password must be at least 6 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.");

    }
}
