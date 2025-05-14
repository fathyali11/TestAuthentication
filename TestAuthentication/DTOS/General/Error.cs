namespace TestAuthentication.DTOS.General;

public record Error(string Code,string Description,int ?StatusCode)
{
    public readonly Error None = new Error(string.Empty, string.Empty, null);
}
