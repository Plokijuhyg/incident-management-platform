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

    /// <summary>
    /// Seeds a dedicated, least-privilege account for machine-to-machine
    /// ingestion (e.g. the HexStrike connector script). SocAnalyst role only
    /// — per api-design.md §5, any authenticated role may POST an alert;
    /// this account should never hold Admin/SecurityManager.
    /// </summary>
    public static async Task SeedIntegrationAccountAsync(
        AppDbContext context,
        IPasswordHasher passwordHasher,
        string? email,
        string? password,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            return; // optional — silently skipped if not configured
        }

        var normalizedEmail = email.Trim().ToLowerInvariant();

        var alreadyExists = await context.Users.AnyAsync(u => u.Email == normalizedEmail, cancellationToken);
        if (alreadyExists)
        {
            return;
        }

        var socRole = await context.Roles.SingleOrDefaultAsync(r => r.Name == RoleNames.SocAnalyst, cancellationToken);
        if (socRole is null)
        {
            logger.LogWarning("Cannot seed integration account: SOC_ANALYST role not found yet.");
            return;
        }

        var adminForAttribution = await context.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
            .FirstOrDefaultAsync(u => u.UserRoles.Any(ur => ur.Role.Name == RoleNames.Admin), cancellationToken);

        var now = DateTime.UtcNow;

        var integrationUser = new User
        {
            Email = normalizedEmail,
            FullName = "HexStrike Connector (Service Account)",
            PasswordHash = passwordHasher.Hash(password),
            IsActive = true,
            CreatedAt = now,
            UpdatedAt = now
        };

        context.Users.Add(integrationUser);
        await context.SaveChangesAsync(cancellationToken); // generates Id

        context.UserRoles.Add(new UserRole
        {
            UserId = integrationUser.Id,
            RoleId = socRole.Id,
            AssignedAt = now,
            AssignedById = adminForAttribution?.Id ?? integrationUser.Id
        });

        await context.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Seeded integration service account {Email}", normalizedEmail);
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
        await context.SaveChangesAsync(cancellationToken);

        context.UserRoles.Add(new UserRole
        {
            UserId = adminUser.Id,
            RoleId = adminRole.Id,
            AssignedAt = DateTime.UtcNow,
            AssignedById = adminUser.Id
        });

        await context.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Seeded initial admin user {Email}", normalizedEmail);
    }
}
