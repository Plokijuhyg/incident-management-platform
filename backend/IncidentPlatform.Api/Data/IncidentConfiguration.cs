using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class IncidentConfiguration : IEntityTypeConfiguration<Incident>
{
    public void Configure(EntityTypeBuilder<Incident> builder)
    {
        builder.ToTable("Incidents");

        builder.HasKey(i => i.Id);

        builder.Property(i => i.IncidentNumber).HasMaxLength(20).IsRequired();
        builder.Property(i => i.Title).HasMaxLength(200).IsRequired();
        builder.Property(i => i.Description).HasColumnType("text").IsRequired();
        builder.Property(i => i.ResolutionSummary).HasColumnType("text");
        builder.Property(i => i.FalsePositiveReason).HasMaxLength(500);

        builder.Property(i => i.Severity).HasConversion<string>().HasMaxLength(20).IsRequired();
        builder.Property(i => i.Priority).HasConversion<string>().HasMaxLength(20).IsRequired();
        builder.Property(i => i.Status).HasConversion<string>().HasMaxLength(20).IsRequired();
        builder.Property(i => i.Category).HasConversion<string>().HasMaxLength(30).IsRequired();
        builder.Property(i => i.Source).HasConversion<string>().HasMaxLength(20).IsRequired();

        builder.Property(i => i.DetectedAt).HasColumnType("datetime(6)");
        builder.Property(i => i.CreatedAt).HasColumnType("datetime(6)");
        builder.Property(i => i.UpdatedAt).HasColumnType("datetime(6)");
        builder.Property(i => i.TriagedAt).HasColumnType("datetime(6)");
        builder.Property(i => i.ContainedAt).HasColumnType("datetime(6)");
        builder.Property(i => i.ResolvedAt).HasColumnType("datetime(6)");
        builder.Property(i => i.ClosedAt).HasColumnType("datetime(6)");

        // The backstop from database-design.md §3.3: even if the sequence
        // table logic (Phase 5) has a bug, the database itself refuses a
        // duplicate incident number rather than allowing two incidents to
        // share an identity.
        builder.HasIndex(i => i.IncidentNumber).IsUnique();

        // The standard dashboard filters.
        builder.HasIndex(i => i.Status);
        builder.HasIndex(i => i.Severity);
        builder.HasIndex(i => i.Category);

        // "My open incidents" — the single most frequent analyst query.
        builder.HasIndex(i => new { i.AssignedToId, i.Status });

        // Date-range filters and time-series charts.
        builder.HasIndex(i => i.CreatedAt);
        builder.HasIndex(i => i.DetectedAt);

        // The open-critical dashboard tile.
        builder.HasIndex(i => new { i.Status, i.Severity });

        // Two separate FKs to Users — same pattern as UserRole's UserId /
        // AssignedById, and for the same reason: EF Core cannot infer which
        // navigation property pairs with which FK when there are two
        // relationships to the same entity, so both are configured
        // explicitly.
        builder.HasOne(i => i.CreatedBy)
            .WithMany()
            .HasForeignKey(i => i.CreatedById)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(i => i.AssignedTo)
            .WithMany()
            .HasForeignKey(i => i.AssignedToId)
            .OnDelete(DeleteBehavior.Restrict);

        // Optimistic concurrency: MySQL has no auto-updating rowversion, so
        // this is a plain int column that EF Core treats as the concurrency
        // token. The service increments it manually on every update
        // (Phase 5) — EF Core's role here is only to include it in the
        // WHERE clause of UPDATE statements and throw
        // DbUpdateConcurrencyException on a mismatch.
        builder.Property(i => i.Version).IsConcurrencyToken();
    }
}
