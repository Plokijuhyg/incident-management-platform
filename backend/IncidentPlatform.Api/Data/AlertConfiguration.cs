using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class AlertConfiguration : IEntityTypeConfiguration<Alert>
{
    public void Configure(EntityTypeBuilder<Alert> builder)
    {
        builder.ToTable("Alerts");

        builder.Property(x => x.EnrichmentJson).HasColumnType("json");

        builder.HasKey(a => a.Id);

        builder.Property(a => a.Title).HasMaxLength(200).IsRequired();
        builder.Property(a => a.Description).HasColumnType("text");
        builder.Property(a => a.SourceRuleId).HasMaxLength(100);
        builder.Property(a => a.ExternalId).HasMaxLength(100);
        builder.Property(a => a.DeduplicationKey).HasMaxLength(200);
        builder.Property(a => a.Severity).HasMaxLength(20).IsRequired();

        builder.Property(a => a.Host).HasMaxLength(255);
        builder.Property(a => a.Username).HasMaxLength(255);
        builder.Property(a => a.EntityIp).HasMaxLength(45);

        builder.Property(a => a.Source).HasConversion<string>().HasMaxLength(20).IsRequired();
        builder.Property(a => a.Status).HasConversion<string>().HasMaxLength(20).IsRequired();

        // Native MySQL json column — RawPayload is stored verbatim, never
        // parsed into typed columns (database-design.md §4.4).
        builder.Property(a => a.RawPayload).HasColumnType("json");

        builder.Property(a => a.DetectedAt).HasColumnType("datetime(6)");
        builder.Property(a => a.ReceivedAt).HasColumnType("datetime(6)");
        builder.Property(a => a.TriagedAt).HasColumnType("datetime(6)");

        builder.HasIndex(a => a.Status);
        builder.HasIndex(a => a.IncidentId);
        builder.HasIndex(a => a.Source);
        builder.HasIndex(a => a.DetectedAt);
        builder.HasIndex(a => a.DeduplicationKey).IsUnique();
        // Correlation scans recent New, unlinked alerts grouped by entity.
        builder.HasIndex(a => new { a.Status, a.IncidentId, a.ReceivedAt });
        builder.HasIndex(a => a.Host);

        // SET NULL, not RESTRICT or CASCADE: an alert predates and outlives
        // its incident (database-design.md §5) — if the incident is ever
        // removed, the alert should revert to unpromoted, not be deleted or
        // block the incident's removal.
        builder.HasOne(a => a.Incident)
            .WithMany()
            .HasForeignKey(a => a.IncidentId)
            .OnDelete(DeleteBehavior.SetNull);

        // TriagedBy -> Users: RESTRICT, per the blanket policy.
        builder.HasOne(a => a.TriagedBy)
            .WithMany()
            .HasForeignKey(a => a.TriagedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
