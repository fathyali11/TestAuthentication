﻿using OneOf;
using TestAuthentication.DTOS.General;
using TestAuthentication.DTOS.Requests;
using TestAuthentication.DTOS.Responses;

namespace TestAuthentication.Services.AuthService;

public interface IAuthServices
{
    Task<OneOf<List<ValidationError>,Error,bool>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>, AuthResponse, Error>> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>,AuthResponse,Error,bool>> ConfirmEmailAsync(ConfirmEmailRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>,bool, Error>> ResendEmailConfirmationAsync(ResendEmailConfirmationRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>,bool,Error>> ForgetPasswordAsync(ForgetPasswordRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>,AuthResponse, Error>> ResetPasswordAsync(ResetPasswordRequest request, CancellationToken cancellationToken = default);
    Task<OneOf<List<ValidationError>, bool, Error>> AddToRoleAsync(AddToRoleRequest request, CancellationToken cancellationToken = default);
}
