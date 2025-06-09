using FluentValidation;
using TestAuthentication.DTOS.General;

namespace TestAuthentication.Services.General;

public class ValidationService(ILogger<ValidationService> _logger)
{
    public async Task<List<ValidationError>?> ValidateRequest<TSource, TRequest>(TSource source, TRequest request)
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

    public async Task<string?> SaveImageToLocal(IFormFile imageFile)
    {
        if (imageFile != null && imageFile.Length > 0)
        {
            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/images");

            if (!Directory.Exists(uploadsFolder))
                Directory.CreateDirectory(uploadsFolder);

            // Generate a unique file name to avoid overwriting
            var uniqueFileName = $"{Guid.NewGuid().ToString()}_{imageFile.FileName}";
            var filePath = Path.Combine(uploadsFolder, uniqueFileName)
                .Replace("\\", "/").Replace(" ", "");

            // Save the file to the local directory
            using (var fileStream = new FileStream(filePath, FileMode.Create))
                await imageFile.CopyToAsync(fileStream);

            return filePath;
        }
        return null;
    }

    public void RemoveOldProfilePictureAsync(string oldPicturePath, CancellationToken cancellationToken = default)
    {
        if (!string.IsNullOrEmpty(oldPicturePath))
        {
            if (File.Exists(oldPicturePath))
            {
                File.Delete(oldPicturePath);
                _logger.LogInformation("Old profile picture removed successfully ");
            }
        }
    }
}
