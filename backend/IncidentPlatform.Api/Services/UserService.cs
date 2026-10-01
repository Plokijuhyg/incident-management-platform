using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Users;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public class UserService : IUserService
{
    private readonly AppDbContext _dbContext;
    private readonly IPasswordHasher _passwordHasher;
    private readonly ICurrentUser _currentUser;

    public UserService(AppDbContext dbContext, IPasswordHasher passwordHasher, ICurrentUser currentUser)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _currentUser = currentUser;
    }

    public async Task<PagedResult<UserResponse>> GetPagedAsync(int page, int pageSize, CancellationToken cancellationToken = default)
    {
        page = Math.Max(page, 1);
        pageSize = Math.Clamp(pageSize, 1, 100);

        var query = _dbContext.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
            .OrderBy(u => u.FullName)
            .AsQueryable();

        var totalCount = await query.CountAsync(cancellationToken);

        var items = await query
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        return new PagedResult<UserResponse>
        {
            Items = items.Select(user => ToResponse(user)).ToList(),
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount
        };
    }

    public async Task<UserResponse> GetByIdAsync(int id, CancellationToken cancellationToken = default)
    {
        var user = await FindOrThrowAsync(id, cancellationToken);
        return ToResponse(user);
    }

    public async Task<UserResponse> CreateAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = request.Email.Trim().ToLowerInvariant();

        var emailTaken = await _dbContext.Users.AnyAsync(u => u.Email == normalizedEmail, cancellationToken);
        if (emailTaken)
        {
            throw new ConflictException($"A user with email '{normalizedEmail}' already exists.");
        }

        var roles = await ResolveRolesOrThrowAsync(request.Roles, cancellationToken);

        var now = DateTime.UtcNow;
        var user = new User
        {
            Email = normalizedEmail,
            FullName = request.FullName,
            PasswordHash = _passwordHasher.Hash(request.Password),
            JobTitle = request.JobTitle,
            IsActive = true,
            CreatedAt = now,
            UpdatedAt = now
        };

        _dbContext.Users.Add(user);
        foreach (var role in roles)
        {
            _dbContext.UserRoles.Add(new UserRole
            {
                User = user,
                RoleId = role.Id,
                AssignedAt = now,
                AssignedById = _currentUser.Id
            });
        }

        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(user, roles.Select(r => r.Name).ToList());
    }

    public async Task<UserResponse> UpdateAsync(int id, UpdateUserRequest request, CancellationToken cancellationToken = default)
    {
        var user = await FindOrThrowAsync(id, cancellationToken);

        user.FullName = request.FullName;
        user.JobTitle = request.JobTitle;
        user.UpdatedAt = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(user);
    }

    public async Task ResetPasswordAsync(int id,string password,CancellationToken cancellationToken=default)
    {
        if(password is null || password.Length is <8 or >128 || !password.Any(char.IsUpper) || !password.Any(char.IsLower) || !password.Any(char.IsDigit))
            throw new ValidationAppException("Use 8-128 characters including uppercase, lowercase and a digit.");
        var user=await FindOrThrowAsync(id,cancellationToken);
        if(!user.IsActive)throw new ValidationAppException("This account is deactivated. Create an active account or review its status first.");
        user.PasswordHash=_passwordHasher.Hash(password);user.UpdatedAt=DateTime.UtcNow;
        user.FailedLoginAttempts=0;user.LockedOutUntil=null;
        var sessions=await _dbContext.RefreshTokens.Where(t=>t.UserId==id && t.RevokedAt==null).ToListAsync(cancellationToken);
        foreach(var session in sessions){session.RevokedAt=DateTime.UtcNow;session.ReasonRevoked="Administrator password reset";}
        _dbContext.AuditLogs.Add(new(){Action="PASSWORD_RESET",EntityType="User",EntityId=id.ToString(),ActorUserId=_currentUser.Id,OccurredAt=DateTime.UtcNow,Outcome=AuditOutcome.Success});
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task DeactivateAsync(int id, CancellationToken cancellationToken = default)
    {
        // Never a hard delete (database-design.md §4.1) — users are
        // referenced by audit logs, timeline events, evidence.
        var user = await FindOrThrowAsync(id, cancellationToken);

        if (user.Id == _currentUser.Id)
        {
            throw new ValidationAppException("You cannot deactivate your own account.");
        }

        user.IsActive = false;
        user.UpdatedAt = DateTime.UtcNow;

        // Deactivation must also kill any active sessions immediately.
        var activeTokens = await _dbContext.RefreshTokens
            .Where(t => t.UserId == id && t.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var t in activeTokens)
        {
            t.RevokedAt = DateTime.UtcNow;
            t.ReasonRevoked = "Account deactivated";
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task<UserResponse> ReplaceRolesAsync(int id, ReplaceRolesRequest request, CancellationToken cancellationToken = default)
    {
        var user = await FindOrThrowAsync(id, cancellationToken);
        var newRoles = await ResolveRolesOrThrowAsync(request.Roles, cancellationToken);

        var existingLinks = await _dbContext.UserRoles.Where(ur => ur.UserId == id).ToListAsync(cancellationToken);
        if (id == _currentUser.Id && !newRoles.Any(r => r.Name == RoleNames.Admin))
            throw new ValidationAppException("You cannot remove your own Admin role.");

        _dbContext.UserRoles.RemoveRange(existingLinks.Where(link => !newRoles.Any(r => r.Id == link.RoleId)));

        var now = DateTime.UtcNow;
        foreach (var role in newRoles.Where(r => !existingLinks.Any(link => link.RoleId == r.Id)))
        {
            _dbContext.UserRoles.Add(new UserRole
            {
                UserId = id,
                RoleId = role.Id,
                AssignedAt = now,
                AssignedById = _currentUser.Id
            });
        }

        await _dbContext.SaveChangesAsync(cancellationToken);

        return ToResponse(user, newRoles.Select(r => r.Name).ToList());
    }

    public async Task<List<RoleResponse>> GetRolesAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.Roles
            .OrderBy(r => r.Name)
            .Select(r => new RoleResponse { Id = r.Id, Name = r.Name, Description = r.Description })
            .ToListAsync(cancellationToken);
    }

    public async Task<List<AssignableUserResponse>> GetAssignableAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.Users
            .Where(u => u.IsActive)
            .OrderBy(u => u.FullName)
            .Select(u => new AssignableUserResponse { Id = u.Id, FullName = u.FullName })
            .ToListAsync(cancellationToken);
    }

    private async Task<User> FindOrThrowAsync(int id, CancellationToken cancellationToken)
    {
        var user = await _dbContext.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
            .SingleOrDefaultAsync(u => u.Id == id, cancellationToken);

        return user ?? throw new NotFoundException("User", id);
    }

    private async Task<List<Role>> ResolveRolesOrThrowAsync(List<string> roleNames, CancellationToken cancellationToken)
    {
        var roles = await _dbContext.Roles.Where(r => roleNames.Contains(r.Name)).ToListAsync(cancellationToken);

        var missing = roleNames.Except(roles.Select(r => r.Name)).ToList();
        if (missing.Count > 0)
        {
            throw new ValidationAppException($"Unknown role name(s): {string.Join(", ", missing)}");
        }

        return roles;
    }

    private static UserResponse ToResponse(User u, List<string>? rolesOverride = null) => new()
    {
        Id = u.Id,
        Email = u.Email,
        FullName = u.FullName,
        JobTitle = u.JobTitle,
        IsActive = u.IsActive,
        LastLoginAt = u.LastLoginAt,
        Roles = rolesOverride ?? u.UserRoles.Select(ur => ur.Role.Name).ToList(),
        CreatedAt = u.CreatedAt
    };
}