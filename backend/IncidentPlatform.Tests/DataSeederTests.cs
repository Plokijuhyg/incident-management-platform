using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace IncidentPlatform.Tests;

public class DataSeederTests
{
    private static AppDbContext CreateInMemoryContext()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        return new AppDbContext(options);
    }

    [Fact]
    public async Task SeedAsync_OnEmptyDatabase_CreatesAllThreeRoles()
    {
        await using var context = CreateInMemoryContext();

        await DataSeeder.SeedAsync(context);

        var roleNames = await context.Roles.Select(r => r.Name).ToListAsync();

        Assert.Equal(3, roleNames.Count);
        Assert.Contains(RoleNames.Admin, roleNames);
        Assert.Contains(RoleNames.SecurityManager, roleNames);
        Assert.Contains(RoleNames.SocAnalyst, roleNames);
    }

    [Fact]
    public async Task SeedAsync_RunTwice_DoesNotCreateDuplicates()
    {
        await using var context = CreateInMemoryContext();

        await DataSeeder.SeedAsync(context);
        await DataSeeder.SeedAsync(context); // run again, simulating a second app startup

        var totalRoleCount = await context.Roles.CountAsync();

        Assert.Equal(3, totalRoleCount);
    }
}
