using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Users;

namespace IncidentPlatform.Api.Interfaces;

public interface IUserService
{
    Task<PagedResult<UserResponse>> GetPagedAsync(int page, int pageSize, CancellationToken cancellationToken = default);

    Task<UserResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default);

    Task<UserResponse> CreateAsync(CreateUserRequest request, CancellationToken cancellationToken = default);

    Task<UserResponse> UpdateAsync(int id, UpdateUserRequest request, CancellationToken cancellationToken = default);

    Task ResetPasswordAsync(int id, string password, CancellationToken cancellationToken = default);

    Task DeactivateAsync(int id, CancellationToken cancellationToken = default);

    Task<UserResponse> ReplaceRolesAsync(int id, ReplaceRolesRequest request, CancellationToken cancellationToken = default);

    Task<List<RoleResponse>> GetRolesAsync(CancellationToken cancellationToken = default);

    Task<List<AssignableUserResponse>> GetAssignableAsync(CancellationToken cancellationToken = default);
}
