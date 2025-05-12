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

namespace TestAuthentication.Services;

public class AuthServices(IOptions<JwtConfig> options,UserManager<ApplicationUser> _userManager) : IAuthServices
{
    private readonly JwtConfig _jwtConfig = options.Value;
    public async Task<AuthResponse> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        var userIsExist =await _userManager.FindByEmailAsync(request.Email);
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
        var result= await _userManager.CreateAsync(user, request.Password);
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
            Username = user.UserName,
            Email = user.Email,
            Token =generateTokenResult.Item1,
            ExpiresAt = generateTokenResult.Item2,
            RefreshToken = GenerateRefreshToken(),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(_jwtConfig.RefreshExpireTime),
            Message= "User created successfully",
            IsSuccess = true
        };


    }
    public Task<AuthResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }


    private (string,DateTime) GenerateToken(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub,user.UserName!),
            new Claim(JwtRegisteredClaimNames.Email,user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
            new Claim("Address",user.Address)
        };
        var key= new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.Key));
        var signingCredentials = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);
        var expiresAt = DateTime.UtcNow.AddMinutes(_jwtConfig.ExpireTime);
        var token = new JwtSecurityToken(
            issuer: _jwtConfig.Issuer,
            audience: _jwtConfig.Audience,
            claims: claims,
            expires: expiresAt,
            signingCredentials: signingCredentials
            );
        return (new JwtSecurityTokenHandler().WriteToken(token),expiresAt);
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
}
