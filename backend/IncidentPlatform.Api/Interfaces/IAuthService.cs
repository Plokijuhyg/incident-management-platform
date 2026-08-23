using IncidentPlatform.Api.DTOs.Auth;

namespace IncidentPlatform.Api.Interfaces;

public interface IAuthService
{
    Task<LoginResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default);
}
