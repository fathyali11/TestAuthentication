using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TestAuthentication.Constants;
using TestAuthentication.DTOS;
using TestAuthentication.Models;
using TestAuthentication.Services.EmailServices;

namespace TestAuthentication.Services.AuthService;

public class AuthServices(IOptions<JwtConfig> options
    , IEmailService _emailSender
    , UserManager<ApplicationUser> _userManager,
    IHttpContextAccessor _httpContextAccessor) : IAuthServices
{
    private readonly JwtConfig _jwtConfig = options.Value;
    public async Task<AuthResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var userIsExist = await _userManager.FindByEmailAsync(request.Email);
        if (userIsExist is not null)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "User already exist"
            };

        var user = new ApplicationUser
        {
            UserName = request.Username,
            Email = request.Email,
            Address = request.Address
        };
        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "internal server error"
            };

        await SendEmailConfirmation(user);
        return new AuthResponse
        {
            Message = "User logged in successfully confirm your email",
            IsSuccess = true
        };
    }
    public async Task<AuthResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByNameAsync(request.Username);
        if (user is null)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "User not exist"
            };
        if(!user.EmailConfirmed)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "Email not confirmed"
            };
        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!isPasswordValid)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "Invalid password"
            };
        var generateTokenResult = GenerateToken(user);
        return new AuthResponse
        {
            Id = user.Id,
            Username = user.UserName!,
            Email = user.Email!,
            Token = generateTokenResult.Item1,
            ExpiresAt = generateTokenResult.Item2,
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtConfig.RefreshExpireTime),
            Message = "User created successfully",
            IsSuccess = true
        };

    }
    public async Task<AuthResponse> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(request.UserId);
        if (user is null)
            return new AuthResponse
            {
                IsSuccess = true,
                Message = "Done"
            };

        var result = await _userManager.ConfirmEmailAsync(user, request.Token);
        if (!result.Succeeded)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "internal server error"
            };

        var generateTokenResult = GenerateToken(user);
        return new AuthResponse
        {
            Id = user.Id,
            Username = user.UserName!,
            Email = user.Email!,
            Token = generateTokenResult.Item1,
            ExpiresAt = generateTokenResult.Item2,
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtConfig.RefreshExpireTime),
            Message = "User confirmed successfully",
            IsSuccess = true
        };
    }
    public async Task<AuthResponse> ResendEmailConfirmationAsync(string email, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "User not exist"
            };
        await SendEmailConfirmation(user);
        return new AuthResponse
        {
            Message = "User logged in successfully confirm your email",
            IsSuccess = true
        };
    }
    public async Task<AuthResponse> ForgetPasswordAsync(string email,CancellationToken cancellationToken=default)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "User not exist"
            };
        await SendForgetPassword(user);
        return new AuthResponse
        {
            Message = "email sent reset your password",
            IsSuccess = true
        };

    }
    public async Task<AuthResponse> ResetPasswordAsync(string userId, string token,string newPassword, CancellationToken cancellationToken = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "User not exist"
            };

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        if (!result.Succeeded)
            return new AuthResponse
            {
                IsSuccess = false,
                Message = "internal server error"
            };
        var generateTokenResult = GenerateToken(user);
        return new AuthResponse
        {
            Id = user.Id,
            Username = user.UserName!,
            Email = user.Email!,
            Token = generateTokenResult.Item1,
            ExpiresAt = generateTokenResult.Item2,
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtConfig.RefreshExpireTime),
            Message = "User created successfully",
            IsSuccess = true
        };
    }
    private (string, DateTime) GenerateToken(ApplicationUser user)
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
        var expiresAt = DateTime.UtcNow.AddMinutes(_jwtConfig.ExpireTime);
        var token = new JwtSecurityToken(
            issuer: _jwtConfig.Issuer,
            audience: _jwtConfig.Audience,
            claims: claims,
            expires: expiresAt,
            signingCredentials: signingCredentials
            );
        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAt);
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
        var encodedToken = Uri.UnescapeDataString(token);
        Console.WriteLine($"token after encoding {encodedToken}\n\n");
        var confirmationLink = _httpContextAccessor.HttpContext != null
                ? _httpContextAccessor.HttpContext.Request.PathBase + "/api/auth/confirm-email?userId=" + user.Id + "&token=" + token
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
}


