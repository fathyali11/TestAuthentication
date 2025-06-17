namespace UsersManagement.CustomValidations;
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
