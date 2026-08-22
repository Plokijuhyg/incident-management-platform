using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Data;

/// <summary>
/// Deliberately empty of DbSets for now — we're proving the connection works
/// before modeling any entities. Roles/Users/UserRoles are added in the next
/// step, per database-design.md §8's dependency order.
/// </summary>
public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }
}
