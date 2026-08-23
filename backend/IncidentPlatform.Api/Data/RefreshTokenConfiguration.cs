using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens");

        builder.HasKey(r => r.Id);

        // 128 chars gives headroom over a 64-char SHA-256 hex digest, in
        // case the hashing scheme ever changes (e.g. to a longer encoding).
        builder.Property(r => r.TokenHash).HasMaxLength(128).IsRequired();
        builder.Property(r => r.ReplacedByTokenHash).HasMaxLength(128);
        builder.Property(r => r.ReasonRevoked).HasMaxLength(200);

        builder.Property(r => r.CreatedByIp).HasMaxLength(45).IsRequired();
        builder.Property(r => r.RevokedByIp).HasMaxLength(45);

        builder.Property(r => r.ExpiresAt).HasColumnType("datetime(6)");
        builder.Property(r => r.CreatedAt).HasColumnType("datetime(6)");
        builder.Property(r => r.RevokedAt).HasColumnType("datetime(6)");

        // The computed bool properties (IsExpired, IsRevoked, IsActive) are
        // intentionally not mapped to columns — EF Core ignores properties
        // with no setter that can't be reasonably persisted, but being
        // explicit here avoids any ambiguity for future readers.
        builder.Ignore(r => r.IsExpired);
        builder.Ignore(r => r.IsRevoked);
        builder.Ignore(r => r.IsActive);

        // Lookup path for validating an incoming refresh token — this is
        // the single query the refresh endpoint runs on every call.
        builder.HasIndex(r => r.TokenHash).IsUnique();
        builder.HasIndex(r => r.UserId);

        builder.HasOne(r => r.User)
            .WithMany()
            .HasForeignKey(r => r.UserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
