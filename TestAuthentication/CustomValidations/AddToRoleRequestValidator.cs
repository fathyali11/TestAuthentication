namespace UsersManagement.CustomValidations;
public class AddToRoleRequestValidator : AbstractValidator<AddToRoleRequest>
{
    public AddToRoleRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("Email is required")
            .EmailAddress()
            .WithMessage("Invalid email format");
        RuleFor(x => x.RoleName)
            .NotEmpty()
            .WithMessage("Role name is required")
            .MinimumLength(2)
            .WithMessage("Role name must be at least 2 characters long");
    }
}