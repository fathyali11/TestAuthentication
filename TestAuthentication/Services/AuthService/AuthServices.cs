namespace UsersManagement.Services.AuthService;
public class AuthServices(
    IOptions<JwtConfig> options,
    IEmailService _emailSender,
    UserManager<ApplicationUser> _userManager,
    IHttpContextAccessor _httpContextAccessor,
    IMapper _mapper,
    IValidator<RegisterRequest> _reigsterRequestValidator,
    IValidator<LoginRequest> _loginRequestValidator,
    IValidator<ConfirmEmailRequest> _confirmEmailRequestValidator,
    IValidator<ForgetPasswordRequest> _forgetPasswordRequestValidator,
    IValidator<ResetPasswordRequest> _resetPasswordRequestValidator,
    IValidator<ResendEmailConfirmationRequest> _resendEmailConfirmationRequestValidator,
    IValidator<AddToRoleRequest> _addToRoleRequestValidator,
    ILogger<AuthServices> _logger,
    RoleManager<IdentityRole> _roleManager,
    ApplicationDbContext _context,
    BlobStorageServices _blobStorageServices,
    HybridCache _hybridCache
) : IAuthServices
{
    private readonly JwtConfig _jwtConfig = options.Value;

    public async Task<OneOf<List<ValidationError>, Error, bool>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Registering user with email: {Email}", request.Email);

        var validationResult = await ValidateRequest(_reigsterRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for user registration: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Validation passed for user registration");

        var userIsExist = await _userManager.FindByEmailAsync(request.Email);
        if (userIsExist is not null)
        {
            _logger.LogWarning("User already exists with email: {Email}", request.Email);
            return UserError.UserAlreadyExists;
        }

        _logger.LogInformation("Creating new user with email: {Email}", request.Email);
        var user = request.Adapt<ApplicationUser>();
        var imageName=$"{Guid.NewGuid().ToString()}_{request.ProfilePicture.FileName.Replace(" ", "")}";
        user.ProfilePictureUrl = imageName;
        await _blobStorageServices.UploadFileAsync(request.ProfilePicture,imageName);
        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            _logger.LogError("User registration failed: {Errors}", result.Errors);
            return UserError.ServerError;
        }
        await _userManager.AddToRoleAsync(user, AdminRoleAndPermissions.Name);
        await SendEmailConfirmation(user);
        _logger.LogInformation("User registration successful, email confirmation sent to: {Email}", request.Email);
        return true;
    }

    public async Task<OneOf<List<ValidationError>, AuthResponse, Error>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Attempting login for username: {Username}", request.Username);

        var validationResult = await ValidateRequest(_loginRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for login: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Validation passed for login");

        var user = await _userManager.FindByNameAsync(request.Username);
        if (user is null)
        {
            _logger.LogWarning("User not found with username: {Username}", request.Username);
            return UserError.UserNotFound;
        }
        if(await _userManager.IsLockedOutAsync(user))
        {
            _logger.LogWarning("User is locked out: {Username}", request.Username);
            return UserError.IsLocked;
        }

        if (!user.EmailConfirmed)
        {
            _logger.LogWarning("Email not confirmed for user: {Username}", request.Username);
            return UserError.NotConfirmed;
        }

        if(!user.IsEnable)
        {
            _logger.LogWarning("User is not active: {Username}", request.Username);
            return UserError.NotActive;
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!isPasswordValid)
        {
            _logger.LogWarning("Invalid password for user: {Username}", request.Username);
            await _userManager.AccessFailedAsync(user);
            return UserError.InvalidPassword;
        }

        _logger.LogInformation("Login successful for user: {Username}", request.Username);
        await _userManager.ResetAccessFailedCountAsync(user);
        return await GenerateResponse(user,cancellationToken);
    }

    public async Task<OneOf<List<ValidationError>, AuthResponse, Error, bool>> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Confirming email for user ID: {UserId}", request.UserId);

        var validationResult = await ValidateRequest(_confirmEmailRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for email confirmation: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Validation passed for email confirmation");

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user is null)
        {
            _logger.LogWarning("User not found with ID: {UserId}", request.UserId);
            return true;
        }

        if (user.EmailConfirmed)
        {
            _logger.LogInformation("Email already confirmed for user ID: {UserId}", request.UserId);
            return true;
        }

        var decodedBytes = WebEncoders.Base64UrlDecode(request.Token);
        var decodedToken = Encoding.UTF8.GetString(decodedBytes);

        var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
        if (!result.Succeeded)
        {
            _logger.LogError("Email confirmation failed for user ID: {UserId}, Errors: {Errors}", request.UserId, result.Errors);
            return UserError.ServerError;
        }
        
        _logger.LogInformation("Email confirmed successfully for user ID: {UserId}", request.UserId);
        return await GenerateResponse(user,cancellationToken);
    }

    public async Task<OneOf<List<ValidationError>, bool, Error>> ResendEmailConfirmationAsync(ResendEmailConfirmationRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Resending email confirmation for email: {Email}", request.Email);

        var validationResult = await ValidateRequest(_resendEmailConfirmationRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for resending email confirmation: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Validation passed for resending email confirmation");

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            _logger.LogWarning("User not found with email: {Email}", request.Email);
            return UserError.UserNotFound;
        }

        await SendEmailConfirmation(user);
        _logger.LogInformation("Email confirmation resent successfully to: {Email}", request.Email);
        return true;
    }

    public async Task<OneOf<List<ValidationError>, bool, Error>> ForgetPasswordAsync(ForgetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Processing forget password request for email: {Email}", request.Email);

        var validationResult = await ValidateRequest(_forgetPasswordRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for forget password: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Validation passed for forget password");

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            _logger.LogWarning("User not found with email: {Email}", request.Email);
            return UserError.UserNotFound;
        }

        await SendForgetPassword(user);
        _logger.LogInformation("Forget password email sent successfully to: {Email}", request.Email);
        return true;
    }

    public async Task<OneOf<List<ValidationError>, AuthResponse, Error>> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Resetting password for user ID: {UserId}", request.UserId);

        var validationResult = await ValidateRequest(_resetPasswordRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for reset password: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Validation passed for reset password");

        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user is null)
        {
            _logger.LogWarning("User not found with ID: {UserId}", request.UserId);
            return UserError.UserNotFound;
        }

        var decodedBytes = WebEncoders.Base64UrlDecode(request.Token);
        var decodedToken = Encoding.UTF8.GetString(decodedBytes);

        var result = await _userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword);
        if (!result.Succeeded)
        {
            _logger.LogError("Password reset failed for user ID: {UserId}, Errors: {Errors}", request.UserId, result.Errors);
            return UserError.ServerError;
        }

        _logger.LogInformation("Password reset successful for user ID: {UserId}", request.UserId);
        return await GenerateResponse(user, cancellationToken);
    }

    public async Task<OneOf<List<ValidationError>, bool, Error>> AddToRoleAsync(AddToRoleRequest request, CancellationToken cancellationToken = default)
    {
        var validationResult = await ValidateRequest(_addToRoleRequestValidator, request);
        if (validationResult is not null)
        {
            _logger.LogWarning("Validation failed for adding user to role: {Errors}", validationResult);
            return validationResult;
        }
        _logger.LogInformation("Adding user Email: {Email} to role: {RoleName}", request.Email, request.RoleName);
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
        {
            _logger.LogWarning("User not found with Email: {Email}", request.Email);
            return UserError.UserNotFound;
        }
        var roleExists = await _roleManager.RoleExistsAsync(request.RoleName);
        if (!roleExists)
        {
            _logger.LogWarning("Role not found: {RoleName}", request.RoleName);
            return UserError.InvalidToken;
        }
        var isUserInRole = await _userManager.IsInRoleAsync(user, request.RoleName);
        if (isUserInRole)
        {
            _logger.LogWarning("User Email: {Email} is already in role: {RoleName}", request.Email, request.RoleName);
            return UserError.InvalidToken;
        }
        var result = await _userManager.AddToRoleAsync(user, request.RoleName);
        if (!result.Succeeded)
        {
            _logger.LogError("Failed to add user Email: {Email} to role: {RoleName}, Errors: {Errors}", request.Email, request.RoleName, result.Errors);
            return UserError.ServerError;
        }
        _logger.LogInformation("User Email: {Email} added to role: {RoleName} successfully", request.Email, request.RoleName);
        return true;
    }

    public async Task<OneOf<AuthResponse, Error>> GenerateTokenForExternalLogin(AuthenticateResult result ,CancellationToken cancellationToken=default)
    {
        if(!result.Succeeded)
            return UserError.InvalidToken;

        var email= result.Principal?.FindFirstValue(ClaimTypes.Email);
        if(string.IsNullOrEmpty(email))
        {
            _logger.LogWarning("Email not found in external login result");
            return UserError.InvalidEmail;
        }
        _logger.LogInformation("Processing external login for email: {Email}", email);

        var user = await _userManager.FindByEmailAsync(email);
        if(user is null)
        {
            _logger.LogInformation("User not found with email: {Email}, creating new user", email);
            var imagePath=$"{Directory.GetCurrentDirectory()}/wwwroot/images/Screenshot20250-18175857.png";
            var imageName = $"{Guid.NewGuid().ToString()}_{Path.GetFileName(imagePath)}";
            using var stream = new FileStream(imagePath, FileMode.Open, FileAccess.Read);
            await _blobStorageServices.UploadStreamAsync(stream, imageName);

            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
                IsEnable = true ,
                CreatedAt=DateTime.UtcNow,
                ProfilePictureUrl=imageName
            };
            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                _logger.LogError("Failed to create user for external login: {Errors}", createResult.Errors);
                return UserError.ServerError;
            }
            _logger.LogInformation("New user created successfully with email: {Email}", email);
            _logger.LogInformation("add to customer role for user: {Email}",email);
            await _userManager.AddToRoleAsync(user, CustomerRoleAndPermissions.Name);
            _logger.LogInformation("User added to customer role successfully for email: {Email}", email);
        }
        else
        {
            _logger.LogInformation("User found with email: {Email}, proceeding with login", email);
        }

        return await GenerateResponse(user,cancellationToken);  
    }

    private (string, int) GenerateToken(ApplicationUser user,List<string>permissions)
    {
        _logger.LogInformation("Generating JWT token for user: {Username}", user.UserName);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id!),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("Address", user.Address),
            new Claim(AdminRoleAndPermissions.Type, JsonSerializer.Serialize(permissions),JsonClaimValueTypes.JsonArray)
        };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.Key));
        var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _jwtConfig.Issuer,
            audience: _jwtConfig.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtConfig.ExpireTime),
            signingCredentials: signingCredentials
        );
        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        _logger.LogInformation("JWT token generated successfully for user: {Username}", user.UserName);
        return (tokenString, _jwtConfig.ExpireTime);
    }

    private string GenerateRefreshToken()
    {
        _logger.LogInformation("Generating refresh token");
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            var refreshToken = Convert.ToBase64String(randomNumber);
            _logger.LogInformation("Refresh token generated successfully");
            return refreshToken;
        }
    }

    private async Task SendEmailConfirmation(ApplicationUser user)
    {
        _logger.LogInformation("Preparing to send email confirmation for user: {Email}", user.Email);

        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        _logger.LogInformation("Generated email confirmation token for user: {Email}", user.Email);

        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var encodedToken = WebEncoders.Base64UrlEncode(tokenBytes);

        var confirmationLink = _httpContextAccessor.HttpContext != null
            ? $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/api/auth/confirm-email?UserId={user.Id}&Token={encodedToken}"
            : throw new InvalidOperationException("HttpContext is not available");


        _logger.LogInformation("Generated confirmation link: {ConfirmationLink}", confirmationLink);

        var emailBody = $@"<h2>مرحبًا {user.UserName}</h2>
                         <p>شكرًا لتسجيلك في تطبيقنا!</p>
                         <p>اضغط على الرابط ده عشان تفعّل حسابك:</p>
                         <a href='{confirmationLink}' style='padding: 10px; background-color: #28a745; color: white; text-decoration: none;'>تفعيل الحساب</a>
                         <p>لو الرابط مش شغال، انسخه والصقه في المتصفح:</p>
                         <p>{confirmationLink}</p>";
        _logger.LogInformation("Enqueuing email confirmation for user: {Email}", user.Email);
        BackgroundJob.Enqueue(() => _emailSender.SendEmailAsync(user.Email!, "تفعيل حسابك", emailBody));
        _logger.LogInformation("Email confirmation enqueued successfully for user: {Email}", user.Email);
    }

    private async Task SendForgetPassword(ApplicationUser user)
    {
        _logger.LogInformation("Preparing to send forget password email for user: {Email}", user.Email);

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        _logger.LogInformation("Generated password reset token for user: {Email}", user.Email);

        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var encodedToken = WebEncoders.Base64UrlEncode(tokenBytes);

        var resetLink = _httpContextAccessor.HttpContext != null
            ? $"{_httpContextAccessor.HttpContext.Request.Scheme}://{_httpContextAccessor.HttpContext.Request.Host}/api/auth/resetpassword?userId={user.Id}&token={encodedToken}"
            : throw new InvalidOperationException("HttpContext is not available");
        _logger.LogInformation("Generated password reset link: {ResetLink}", resetLink);

        var emailBody = $@"<h2>إعادة تعيين كلمة السر</h2>
                      <p>اضغط على الرابط ده عشان تعيد تعيين كلمة السر:</p>
                      <a href='{resetLink}' style='padding: 10px; background-color: #28a745; color: white; text-decoration: none;'>إعادة تعيين كلمة السر</a>
                      <p>لو الرابط مش شغال، انسخه والصقه في المتصفح:</p>
                      <p>{resetLink}</p>";
        _logger.LogInformation("Enqueuing forget password email for user: {Email}", user.Email);
        BackgroundJob.Enqueue(() => _emailSender.SendEmailAsync(user.Email!, "إعادة تعيين كلمة السر", emailBody));
        _logger.LogInformation("Forget password email enqueued successfully for user: {Email}", user.Email);
    }

    private async Task<AuthResponse> GenerateResponse(ApplicationUser user,CancellationToken cancellationToken=default)
    {
        _logger.LogInformation("Generating authentication response for user: {Username}", user.UserName);
        var roles= await _userManager.GetRolesAsync(user);
        var roleName = roles.FirstOrDefault();

        var role =roleName is not null
            ? await _context.Roles.FirstOrDefaultAsync(x => x.Name == roleName, cancellationToken: cancellationToken)
            : null;

        var permissions=await _context.RoleClaims
            .Where(x => x.RoleId == role!.Id)
            .Select(x => x.ClaimValue)
            .ToListAsync(cancellationToken);

        var userData = _mapper.Map<UserData>(user);
        userData.Permissions = permissions!;
        userData.Role = role?.Name??string.Empty;
   
        var pictureUrl= await _blobStorageServices.GetFileUrlAsync(user.ProfilePictureUrl);
        userData.ProfilePictureUrl = pictureUrl.Replace(" ","");

        var generateTokenResult = GenerateToken(user,permissions!);
        var tokenData = new TokenData
        {
            AccessToken = generateTokenResult.Item1,
            AccessTokenExpiresIn = generateTokenResult.Item2,
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpiresIn = DateTime.UtcNow.AddDays(_jwtConfig.RefreshExpireTime)
        };
        await _hybridCache.RemoveAsync("AllUsers",cancellationToken);
        _logger.LogInformation("Authentication response generated successfully for user: {Username}", user.UserName);
        return new AuthResponse
        {
            User = userData,
            Token = tokenData
        };
    }

    private async Task<List<ValidationError>?> ValidateRequest<TSource, TRequest>(TSource source, TRequest request)
        where TSource : IValidator<TRequest>
        where TRequest : class
    {
        _logger.LogInformation("Validating request of type: {RequestType}", typeof(TRequest).Name);

        var validationResult = await source.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            var errors = validationResult.Errors
                .Select(e => new ValidationError(
                    e.PropertyName,
                    e.ErrorMessage
                )).ToList();
            _logger.LogWarning("Validation failed for request type: {RequestType}, Errors: {Errors}", typeof(TRequest).Name, errors);
            return errors;
        }

        _logger.LogInformation("Validation successful for request type: {RequestType}", typeof(TRequest).Name);
        return null;
    }

    
}