namespace TestAuthentication.CustomValidations;
public class UpdateProfilePictureRequestValidator: AbstractValidator<UpdateProfilePictureRequest>
{
    public UpdateProfilePictureRequestValidator()
    {
        RuleFor(x => x.ProfilePicture)
            .NotNull()
            .WithMessage("Profile picture is required")
            .Must(file => file.Length > 0)
            .WithMessage("Profile picture cannot be empty")
            .Must(file => file.ContentType == "image/jpeg" || file.ContentType == "image/png")
            .WithMessage("Profile picture must be a JPEG or PNG image");
    }
}
