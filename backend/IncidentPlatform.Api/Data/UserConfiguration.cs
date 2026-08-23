using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        builder.ToTable("Users");

        builder.HasKey(u => u.Id);

        builder.Property(u => u.Email)
            .HasMaxLength(256)
            .IsRequired();

        builder.Property(u => u.FullName)
            .HasMaxLength(150)
            .IsRequired();

        // ASP.NET Core Identity's PBKDF2 hash format fits comfortably within
        // 255 chars — this is never a plaintext or reversible value.
        builder.Property(u => u.PasswordHash)
            .HasMaxLength(255)
            .IsRequired();

        builder.Property(u => u.JobTitle)
            .HasMaxLength(100);

        builder.Property(u => u.IsActive)
            .HasDefaultValue(true);

        builder.Property(u => u.FailedLoginAttempts)
            .HasDefaultValue(0);

        // datetime(6) per database-design.md §1 — microsecond precision,
        // matching MySQL's maximum fractional-seconds support.
        builder.Property(u => u.LastLoginAt).HasColumnType("datetime(6)");
        builder.Property(u => u.LockedOutUntil).HasColumnType("datetime(6)");
        builder.Property(u => u.CreatedAt).HasColumnType("datetime(6)");
        builder.Property(u => u.UpdatedAt).HasColumnType("datetime(6)");

        builder.HasIndex(u => u.Email)
            .IsUnique();

        builder.HasIndex(u => u.IsActive);
    }
}
