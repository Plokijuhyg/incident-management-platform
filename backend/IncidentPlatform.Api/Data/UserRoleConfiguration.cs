using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class UserRoleConfiguration : IEntityTypeConfiguration<UserRole>
{
    public void Configure(EntityTypeBuilder<UserRole> builder)
    {
        builder.ToTable("UserRoles");

        builder.HasKey(ur => new { ur.UserId, ur.RoleId });

        builder.Property(ur => ur.AssignedAt)
            .HasColumnType("datetime(6)")
            .IsRequired();

        // A user can hold multiple roles (the User -> UserRoles side), so
        // this relationship must NOT cascade-delete — deleting one role
        // assignment must never touch the user or their other roles.
        // RESTRICT here matches "Any -> Users: RESTRICT" from
        // database-design.md §5: users are deactivated, never deleted, so
        // this path should realistically never fire, but the constraint is
        // the backstop if application logic is ever wrong.
        builder.HasOne(ur => ur.User)
            .WithMany(u => u.UserRoles)
            .HasForeignKey(ur => ur.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(ur => ur.Role)
            .WithMany(r => r.UserRoles)
            .HasForeignKey(ur => ur.RoleId)
            .OnDelete(DeleteBehavior.Restrict);

        // AssignedBy is a second, separate FK to Users (who granted this
        // role), distinct from UserId (who received it). EF Core needs
        // OnDelete(Restrict) here too, and — critically — needs this
        // relationship configured explicitly, since two FKs to the same
        // entity (User) from UserRole is ambiguous for EF Core to infer
        // automatically.
        builder.HasOne(ur => ur.AssignedBy)
            .WithMany()
            .HasForeignKey(ur => ur.AssignedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
