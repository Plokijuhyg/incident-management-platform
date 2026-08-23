using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Data;

/// <summary>
/// Idempotent startup seeding for reference data — per database-design.md
/// §6, this runs at application startup (not inside a migration), so
/// reference data can be extended later without a schema change.
///
/// Only Roles are seeded here. The admin user (also specified in §6) is
/// deferred until Phase 6, once a real password hasher exists — seeding a
/// user with a throwaway hash now would mean redoing this seeder later.
/// </summary>
public static class DataSeeder
{
    private static readonly (string Name, string Description)[] SeedRoles =
    [
        (RoleNames.Admin, "Full system access: manages users, roles, and all incidents."),
        (RoleNames.SecurityManager, "Broad incident visibility, assignment, and closure approval."),
        (RoleNames.SocAnalyst, "Investigation-focused: assigned incidents, evidence, IOCs, response actions.")
    ];

    public static async Task SeedAsync(AppDbContext context, CancellationToken cancellationToken = default)
    {
        foreach (var (name, description) in SeedRoles)
        {
            // Checked one at a time, rather than "if Roles.Any() skip all",
            // so adding a fourth role name later and re-running seeding
            // inserts only the new one — it doesn't require the table to be
            // empty to do anything useful.
            var exists = await context.Roles.AnyAsync(r => r.Name == name, cancellationToken);

            if (!exists)
            {
                context.Roles.Add(new Role
                {
                    Name = name,
                    Description = description
                });
            }
        }

        await context.SaveChangesAsync(cancellationToken);
    }
}
