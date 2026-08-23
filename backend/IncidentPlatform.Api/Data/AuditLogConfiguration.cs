using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("AuditLogs");

        builder.HasKey(a => a.Id);

        // Explicitly NOT the standard int identity — bigint per
        // database-design.md §4.12, since this table's row count dwarfs
        // every other table's over the application's lifetime.
        builder.Property(a => a.Id).ValueGeneratedOnAdd();

        builder.Property(a => a.ActorEmail).HasMaxLength(256);
        builder.Property(a => a.Action).HasMaxLength(60).IsRequired();
        builder.Property(a => a.EntityType).HasMaxLength(50);
        builder.Property(a => a.EntityId).HasMaxLength(50);

        builder.Property(a => a.Outcome).HasConversion<string>().HasMaxLength(20).IsRequired();

        // 45 chars = max IPv6 text length (database-design.md §4.12).
        builder.Property(a => a.IpAddress).HasMaxLength(45).IsRequired();
        builder.Property(a => a.UserAgent).HasMaxLength(500);

        builder.Property(a => a.Details).HasColumnType("json");

        builder.Property(a => a.OccurredAt).HasColumnType("datetime(6)");

        builder.HasIndex(a => new { a.ActorUserId, a.OccurredAt });
        builder.HasIndex(a => a.Action);
        builder.HasIndex(a => new { a.EntityType, a.EntityId });
        builder.HasIndex(a => a.OccurredAt);

        // Nullable, RESTRICT: system actions and failed logins with an
        // unknown/nonexistent username both leave this null — there's no
        // real user to attribute the action to yet ActorEmail still
        // captures whatever identity was claimed at the time.
        builder.HasOne(a => a.ActorUser)
            .WithMany()
            .HasForeignKey(a => a.ActorUserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
