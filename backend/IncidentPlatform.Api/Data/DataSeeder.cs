using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace IncidentPlatform.Api.Data;

public static class DataSeeder
{
    private static readonly (string Name, string Description)[] SeedRoles =
    [
        (RoleNames.Admin, "Full system access: manages users, roles, and all incidents."),
        (RoleNames.SecurityManager, "Broad incident visibility, assignment, and closure approval."),
        (RoleNames.SocAnalyst, "Investigation-focused: assigned incidents, evidence, IOCs, response actions.")
    ];

    public static async Task SeedAsync(
        AppDbContext context,
        IPasswordHasher passwordHasher,
        string? adminEmail,
        string? adminPassword,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        foreach (var (name, description) in SeedRoles)
        {
            var exists = await context.Roles.AnyAsync(r => r.Name == name, cancellationToken);
            if (!exists)
            {
                context.Roles.Add(new Role { Name = name, Description = description });
            }
        }

        await context.SaveChangesAsync(cancellationToken);

        await SeedAdminUserAsync(context, passwordHasher, adminEmail, adminPassword, logger, cancellationToken);
    }

    private static async Task SeedAdminUserAsync(
        AppDbContext context,
        IPasswordHasher passwordHasher,
        string? adminEmail,
        string? adminPassword,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var adminAlreadyExists = await context.UserRoles
            .Include(ur => ur.Role)
            .AnyAsync(ur => ur.Role.Name == RoleNames.Admin, cancellationToken);

        if (adminAlreadyExists)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(adminEmail) || string.IsNullOrWhiteSpace(adminPassword))
        {
            logger.LogWarning(
                "No admin user exists and Admin:Email/Admin:Password are not configured in User Secrets.");
            return;
        }

        var normalizedEmail = adminEmail.Trim().ToLowerInvariant();
        var adminRole = await context.Roles.SingleAsync(r => r.Name == RoleNames.Admin, cancellationToken);

        var adminUser = new User
        {
            Email = normalizedEmail,
            FullName = "System Administrator",
            PasswordHash = passwordHasher.Hash(adminPassword),
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        context.Users.Add(adminUser);
        await context.SaveChangesAsync(cancellationToken); // generates adminUser.Id

        context.UserRoles.Add(new UserRole
        {
            UserId = adminUser.Id,
            RoleId = adminRole.Id,
            AssignedAt = DateTime.UtcNow,
            AssignedById = adminUser.Id // bootstrap case: no other user exists yet
        });

        await context.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Seeded initial admin user {Email}", normalizedEmail);
    }
}
