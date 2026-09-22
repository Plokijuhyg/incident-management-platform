using IncidentPlatform.Api.DTOs.Auth;

namespace IncidentPlatform.Api.Interfaces;

public interface IAuthService
{
    Task<AuthResult> LoginAsync(LoginRequest request, string ipAddress, CancellationToken cancellationToken = default);

    Task<AuthResult> RefreshAsync(string rawRefreshToken, string ipAddress, CancellationToken cancellationToken = default);

    Task LogoutAsync(string rawRefreshToken, string ipAddress, CancellationToken cancellationToken = default);
}