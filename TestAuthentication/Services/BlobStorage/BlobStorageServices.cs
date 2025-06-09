using Azure.Storage.Blobs;

namespace TestAuthentication.Services.BlobStorage;

public class BlobStorageServices(IConfiguration _configuration,
    ILogger<BlobStorageServices> _logger)
{
    private readonly BlobServiceClient _blobServiceClient= new(_configuration.GetConnectionString("StorageConnection"));
    private static readonly string _containerName = "images";
    public async Task UploadFileAsync(IFormFile file)
    {
        var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
        await containerClient.CreateIfNotExistsAsync();
        var blobClient = containerClient.GetBlobClient(file.FileName.Replace(" ",""));

        using var fileStream = file.OpenReadStream();

        await blobClient.UploadAsync(fileStream, overwrite: true);
    }
    public async Task<string> GetFileUrlAsync(string fileName)
    {
        var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
        var blobClient = containerClient.GetBlobClient(fileName);
        if (await blobClient.ExistsAsync())
        {
            return blobClient.Uri.ToString();
        }
        else
        {
            _logger.LogWarning("File {FileName} does not exist in the blob storage.", fileName);
            throw new FileNotFoundException($"File {fileName} not found in blob storage.");
        }
    }
    public async Task DeleteFileAsync(string fileName)
    {
        var containerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
        var blobClient = containerClient.GetBlobClient(fileName);
        if (await blobClient.ExistsAsync())
        {
            await blobClient.DeleteIfExistsAsync();
            _logger.LogInformation("File {FileName} deleted successfully from blob storage.", fileName);
        }
        else
        {
            _logger.LogWarning("File {FileName} does not exist in the blob storage.", fileName);
            throw new FileNotFoundException($"File {fileName} not found in blob storage.");
        }
    }
    public async Task UpdateFileAsync(IFormFile file, string existingFileName)
    {
        await DeleteFileAsync(existingFileName);
        await UploadFileAsync(file);
    }
}
