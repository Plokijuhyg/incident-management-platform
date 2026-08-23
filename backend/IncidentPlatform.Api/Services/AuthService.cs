using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentPlatform.Api.Services;

public class AuthService : IAuthService
{
    private const int MaxFailedLoginAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    private readonly AppDbContext _dbContext;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtService _jwtService;
    private readonly JwtSettings _jwtSettings;

    public AuthService(
        AppDbContext dbContext,
        IPasswordHasher passwordHasher,
        IJwtService jwtService,
        IOptions<JwtSettings> jwtSettings)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _jwtService = jwtService;
        _jwtSettings = jwtSettings.Value;
    }

    public async Task<LoginResponse> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = request.Email.Trim().ToLowerInvariant();

        var user = await _dbContext.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .SingleOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

        // Same generic exception for "no such user" as for "wrong password"
        // below — api-design.md §2: distinguishing them is a user-
        // enumeration oracle. AuthenticationFailedException maps to 401 via
        // GlobalExceptionHandler, same as every other AppException.
        if (user is null)
        {
            throw new AuthenticationFailedException();
        }

        if (!user.IsActive)
        {
            // Deactivated accounts get the same generic message — telling
            // an attacker "this account exists but is deactivated" is still
            // more than a generic failure should reveal.
            throw new AuthenticationFailedException();
        }

        if (user.LockedOutUntil is not null && user.LockedOutUntil > DateTime.UtcNow)
        {
            throw new AuthenticationFailedException();
        }

        var passwordValid = _passwordHasher.Verify(user.PasswordHash, request.Password);

        if (!passwordValid)
        {
            user.FailedLoginAttempts++;

            if (user.FailedLoginAttempts >= MaxFailedLoginAttempts)
            {
                user.LockedOutUntil = DateTime.UtcNow.Add(LockoutDuration);
            }

            await _dbContext.SaveChangesAsync(cancellationToken);

            throw new AuthenticationFailedException();
        }

        // Successful login resets the failure counter and lockout, and
        // records LastLoginAt.
        user.FailedLoginAttempts = 0;
        user.LockedOutUntil = null;
        user.LastLoginAt = DateTime.UtcNow;
        await _dbContext.SaveChangesAsync(cancellationToken);

        var roleNames = user.UserRoles.Select(ur => ur.Role.Name).ToList();
        var accessToken = _jwtService.GenerateAccessToken(user, roleNames);

        return new LoginResponse
        {
            AccessToken = accessToken,
            ExpiresIn = _jwtSettings.AccessTokenExpirationMinutes * 60,
            User = new LoginUserInfo
            {
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Roles = roleNames
            }
        };
    }
}
