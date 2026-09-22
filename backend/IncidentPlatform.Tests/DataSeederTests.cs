using IncidentPlatform.Api.Authentication;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
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
        var hasher = new PasswordHasher();

        await DataSeeder.SeedAsync(context, hasher, adminEmail: null, adminPassword: null, NullLogger.Instance);

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
        var hasher = new PasswordHasher();

        await DataSeeder.SeedAsync(context, hasher, adminEmail: null, adminPassword: null, NullLogger.Instance);
        await DataSeeder.SeedAsync(context, hasher, adminEmail: null, adminPassword: null, NullLogger.Instance);

        var totalRoleCount = await context.Roles.CountAsync();

        Assert.Equal(3, totalRoleCount);
    }

    [Fact]
    public async Task SeedAsync_WithAdminCredentials_CreatesAdminUserWithAdminRole()
    {
        await using var context = CreateInMemoryContext();
        var hasher = new PasswordHasher();

        await DataSeeder.SeedAsync(
            context, hasher, adminEmail: "admin@test.local", adminPassword: "Password123!", NullLogger.Instance);

        var admin = await context.Users
            .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.Role)
            .SingleOrDefaultAsync(u => u.Email == "admin@test.local");

        Assert.NotNull(admin);
        Assert.Contains(admin!.UserRoles, ur => ur.Role.Name == RoleNames.Admin);
        Assert.True(hasher.Verify(admin.PasswordHash, "Password123!"));
    }

    [Fact]
    public async Task SeedAsync_RunTwiceWithAdminCredentials_DoesNotCreateASecondAdmin()
    {
        await using var context = CreateInMemoryContext();
        var hasher = new PasswordHasher();

        await DataSeeder.SeedAsync(
            context, hasher, adminEmail: "admin@test.local", adminPassword: "Password123!", NullLogger.Instance);
        await DataSeeder.SeedAsync(
            context, hasher, adminEmail: "admin@test.local", adminPassword: "Password123!", NullLogger.Instance);

        var adminCount = await context.Users.CountAsync(u => u.Email == "admin@test.local");
        Assert.Equal(1, adminCount);
    }
}
