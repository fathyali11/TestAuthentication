using FluentValidation;
using Mapster;
using MapsterMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OneOf;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using TestAuthentication.Constants;
using TestAuthentication.Constants.Errors;
using TestAuthentication.CustomValidations;
using TestAuthentication.DTOS.General;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.DTOS.Responses;
using TestAuthentication.Models;
using TestAuthentication.Services.EmailServices;

namespace TestAuthentication.Services.AuthService;

public class AuthServices(IOptions<JwtConfig> options
    , IEmailService _emailSender
    , UserManager<ApplicationUser> _userManager,
    IHttpContextAccessor _httpContextAccessor,IMapper _mapper,
    IValidator<RegisterRequest> _reigsterRequestValidator,
    IValidator<LoginRequest> _loginRequestValidator
    ) : IAuthServices
{
    private readonly JwtConfig _jwtConfig = options.Value;
    public async Task<OneOf<List<ValidationError>,Error,bool>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var validationResult = await _reigsterRequestValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errors = validationResult.Errors
                .Select(e => new ValidationError(
                    e.PropertyName,
                    e.ErrorMessage
                    )
                ).ToList();
            return errors;
        }
        var userIsExist = await _userManager.FindByEmailAsync(request.Email);
        if (userIsExist is not null)
            return UserError.UserAlreadyExists;

        var user = request.Adapt<ApplicationUser>();
        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return UserError.ServerError;
        await SendEmailConfirmation(user);
        return true;
        
    }
    public async Task<OneOf<List<ValidationError>, AuthResponse, Error>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var validationResult = await _loginRequestValidator.ValidateAsync(request, cancellationToken);
        if (!validationResult.IsValid)
        {
            var errors = validationResult.Errors
                .Select(e => new ValidationError(
                    e.PropertyName,
                    e.ErrorMessage
                    )
                ).ToList();
            return errors;
        }
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user is null)
            return UserError.UserNotFound;
        if (!user.EmailConfirmed)
            return UserError.NotConfirmed;  
        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!isPasswordValid)
            return UserError.InvalidPassword;
        return GenerateResponse(user);
    }
    public async Task<OneOf<AuthResponse, Error,bool>> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user is null)
            return true;

        var result = await _userManager.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
            return UserError.ServerError;
        return GenerateResponse(user);
        
    }
    public async Task<OneOf<bool,Error>> ResendEmailConfirmationAsync(ResendEmailConfirmationRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return UserError.UserNotFound;
        await SendEmailConfirmation(user);
        return true;
    }
    public async Task<OneOf<bool, Error>> ForgetPasswordAsync(ForgetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return UserError.UserNotFound;
        await SendForgetPassword(user);
        return true;
    }
    public async Task<OneOf<AuthResponse, Error>> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user is null)
            return UserError.UserNotFound;

        var result = await _userManager.ResetPasswordAsync(user, request.Token,request.NewPassword);
        if (!result.Succeeded)
            return UserError.ServerError;
        var generateTokenResult = GenerateToken(user);
        return GenerateResponse(user);
    }
    private (string, int) GenerateToken(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub,user.UserName!),
            new Claim(JwtRegisteredClaimNames.Email,user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
            new Claim("Address",user.Address)
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
        return (new JwtSecurityTokenHandler().WriteToken(token), _jwtConfig.ExpireTime);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    private async Task SendEmailConfirmation(ApplicationUser user)
    {
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        Console.WriteLine($"token befor encoded {token}\n\n");
        var encodedToken = HttpUtility.UrlEncode(token);
        Console.WriteLine($"token after encoding {encodedToken}\n\n");
        var confirmationLink = _httpContextAccessor.HttpContext != null
                ? _httpContextAccessor.HttpContext.Request.PathBase + "/api/auth/confirm-email?UserId=" + user.Id + "&Token=" + token
                : throw new InvalidOperationException("HttpContext is not available");
        var emailBody = $@"<h2>مرحبًا {user.UserName}</h2>
                             <p>شكرًا لتسجيلك في تطبيقنا!</p>
                             <p>اضغط على الرابط ده عشان تفعّل حسابك:</p>
                             <a href='{confirmationLink}' style='padding: 10px; background-color: #28a745; color: white; text-decoration: none;'>تفعيل الحساب</a>
                             <p>لو الرابط مش شغال، انسخه والصقه في المتصفح:</p>
                             <p>{confirmationLink}</p>";
        await _emailSender.SendEmailAsync(user.Email!, "تفعيل حسابك", emailBody);
    }
    private async Task SendForgetPassword(ApplicationUser user)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var resetLink = _httpContextAccessor.HttpContext != null
            ? _httpContextAccessor.HttpContext.Request.PathBase + "/api/auth/resetpassword?userId=" + user.Id + "&token=" + token
            : throw new InvalidOperationException("HttpContext is not available");

        var emailBody = $@"<h2>إعادة تعيين كلمة السر</h2>
                      <p>اضغط على الرابط ده عشان تعيد تعيين كلمة السر:</p>
                      <a href='{resetLink}' style='padding: 10px; background-color: #28a745; color: white; text-decoration: none;'>إعادة تعيين كلمة السر</a>
                      <p>لو الرابط مش شغال، انسخه والصقه في المتصفح:</p>
                      <p>{resetLink}</p>";
        await _emailSender.SendEmailAsync(user.Email!, "Reset Password", emailBody);
    }
    private AuthResponse GenerateResponse(ApplicationUser user)
    {
        var userData = _mapper.Map<UserData>(user);
        var generateTokenResult = GenerateToken(user);
        var tokenData = new TokenData
        {
            AccessToken = generateTokenResult.Item1,
            AccessTokenExpiresIn = generateTokenResult.Item2,
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpiresIn = DateTime.UtcNow.AddDays(_jwtConfig.RefreshExpireTime)
        };

        return new AuthResponse
        {
            User = userData,
            Token = tokenData
        };
    }
}


