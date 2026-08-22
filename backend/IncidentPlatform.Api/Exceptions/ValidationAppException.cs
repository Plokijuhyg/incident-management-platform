using System.Net;

namespace IncidentPlatform.Api.Exceptions;

/// <summary>
/// Thrown for business-rule validation failures that go beyond what data
/// annotations on a DTO can express — e.g. "incident cannot transition from
/// CLOSED back to NEW". Maps to 400.
///
/// Distinct from ASP.NET Core's automatic model validation (triggered by
/// [ApiController] + data annotations), which already returns 400 before a
/// request reaches a controller action at all. This is for validation that
/// can only happen inside the service layer, once real data is involved.
/// </summary>
public sealed class ValidationAppException : AppException
{
    public override int StatusCode => (int)HttpStatusCode.BadRequest;

    public ValidationAppException(string message) : base(message)
    {
    }
}
