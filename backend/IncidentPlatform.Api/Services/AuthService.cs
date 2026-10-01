using System.Security.Cryptography;
using System.Text;
using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
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
    private readonly IAuditContext? _audit;

    public AuthService(
        AppDbContext dbContext,
        IPasswordHasher passwordHasher,
        IJwtService jwtService,
        IOptions<JwtSettings> jwtSettings, IAuditContext? audit = null)
    {
        _dbContext = dbContext;
        _passwordHasher = passwordHasher;
        _jwtService = jwtService;
        _jwtSettings = jwtSettings.Value;
        _audit = audit;
    }

    public async Task<AuthResult> LoginAsync(LoginRequest request, string ipAddress, CancellationToken cancellationToken = default)
    {
        var normalizedEmail = request.Email.Trim().ToLowerInvariant();

        var user = await _dbContext.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .SingleOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

        if (user is null || !user.IsActive)
        {
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

        user.FailedLoginAttempts = 0;
        user.LockedOutUntil = null;
        user.LastLoginAt = DateTime.UtcNow;

        var (refreshTokenEntity, rawRefreshToken) = GenerateRefreshToken(user, ipAddress);
        _dbContext.RefreshTokens.Add(refreshTokenEntity);
        AddAudit("LOGIN_SUCCEEDED", user);

        await _dbContext.SaveChangesAsync(cancellationToken);

        var roleNames = user.UserRoles.Select(ur => ur.Role.Name).ToList();
        var accessToken = _jwtService.GenerateAccessToken(user, roleNames);

        return BuildAuthResult(user, roleNames, accessToken, rawRefreshToken, refreshTokenEntity.ExpiresAt);
    }

    public async Task<AuthResult> RefreshAsync(string rawRefreshToken, string ipAddress, CancellationToken cancellationToken = default)
    {
        var tokenHash = HashToken(rawRefreshToken);

        var token = await _dbContext.RefreshTokens
            .Include(t => t.User)
                .ThenInclude(u => u.UserRoles)
                    .ThenInclude(ur => ur.Role)
            .SingleOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);

        if (token is null)
        {
            throw new AuthenticationFailedException();
        }

        if (token.IsRevoked)
        {
            await RevokeAllActiveTokensForUserAsync(
                token.UserId, ipAddress, "Attempted reuse of a revoked refresh token", cancellationToken);
            throw new AuthenticationFailedException();
        }

        if (!token.User.IsActive || token.IsExpired)
        {
            throw new AuthenticationFailedException();
        }

        var (newTokenEntity, rawNewToken) = GenerateRefreshToken(token.User, ipAddress);
        _dbContext.RefreshTokens.Add(newTokenEntity);

        token.RevokedAt = DateTime.UtcNow;
        token.RevokedByIp = ipAddress;
        token.ReasonRevoked = "Rotated";
        token.ReplacedByTokenHash = newTokenEntity.TokenHash;
        AddAudit("TOKEN_REFRESHED", token.User);

        await _dbContext.SaveChangesAsync(cancellationToken);

        var roleNames = token.User.UserRoles.Select(ur => ur.Role.Name).ToList();
        var accessToken = _jwtService.GenerateAccessToken(token.User, roleNames);

        return BuildAuthResult(token.User, roleNames, accessToken, rawNewToken, newTokenEntity.ExpiresAt);
    }

    public async Task LogoutAsync(string rawRefreshToken, string ipAddress, CancellationToken cancellationToken = default)
    {
        var tokenHash = HashToken(rawRefreshToken);

        var token = await _dbContext.RefreshTokens
            .SingleOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);

        if (token is not null && !token.IsRevoked)
        {
            token.RevokedAt = DateTime.UtcNow;
            token.RevokedByIp = ipAddress;
            token.ReasonRevoked = "Logged out";
            var user = await _dbContext.Users.SingleAsync(u => u.Id == token.UserId, cancellationToken);
            AddAudit("LOGOUT", user);
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task ChangePasswordAsync(int userId, ChangePasswordRequest request, string ipAddress, CancellationToken cancellationToken = default)
    {
        var user = await _dbContext.Users.SingleOrDefaultAsync(u => u.Id == userId, cancellationToken);

        if (user is null)
        {
            throw new NotFoundException("User", userId);
        }

        if (!_passwordHasher.Verify(user.PasswordHash, request.CurrentPassword))
        {
            throw new ValidationAppException("Current password is incorrect.");
        }

        AddAudit("PASSWORD_CHANGED", user);
        user.PasswordHash = _passwordHasher.Hash(request.NewPassword);
        user.UpdatedAt = DateTime.UtcNow;

        // A password change invalidates every existing session — a stolen
        // session must not survive a password change the real user made.
        var activeTokens = await _dbContext.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var t in activeTokens)
        {
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedByIp = ipAddress;
            t.ReasonRevoked = "Password changed";
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private async Task RevokeAllActiveTokensForUserAsync(int userId, string ipAddress, string reason, CancellationToken cancellationToken)
    {
        var activeTokens = await _dbContext.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var t in activeTokens)
        {
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedByIp = ipAddress;
            t.ReasonRevoked = reason;
        }

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private (RefreshToken Entity, string RawToken) GenerateRefreshToken(User user, string ipAddress)
    {
        var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        var entity = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = HashToken(rawToken),
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpirationDays),
            CreatedAt = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };

        return (entity, rawToken);
    }

    private void AddAudit(string action, User user)
    {
        if (_audit?.IsActive != true) return;
        _audit.ActorUserId = user.Id;
        _audit.ActorEmail = user.Email;
        _dbContext.AuditLogs.Add(_audit.Create(action, "User", user.Id.ToString()));
    }

    private static string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes);
    }

    private AuthResult BuildAuthResult(User user, List<string> roleNames, string accessToken, string rawRefreshToken, DateTime refreshTokenExpiresAt)
    {
        return new AuthResult
        {
            LoginResponse = new LoginResponse
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
            },
            RawRefreshToken = rawRefreshToken,
            RefreshTokenExpiresAt = refreshTokenExpiresAt
        };
    }
}
