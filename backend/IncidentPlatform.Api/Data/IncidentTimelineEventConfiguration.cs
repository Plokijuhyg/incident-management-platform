using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class IncidentTimelineEventConfiguration : IEntityTypeConfiguration<IncidentTimelineEvent>
{
    public void Configure(EntityTypeBuilder<IncidentTimelineEvent> builder)
    {
        builder.ToTable("IncidentTimelineEvents");

        builder.HasKey(e => e.Id);

        builder.Property(e => e.EventType).HasConversion<string>().HasMaxLength(40).IsRequired();
        builder.Property(e => e.Title).HasMaxLength(200).IsRequired();
        builder.Property(e => e.Description).HasColumnType("text");

        builder.Property(e => e.OccurredAt).HasColumnType("datetime(6)");
        builder.Property(e => e.RecordedAt).HasColumnType("datetime(6)");

        // The composite that renders the timeline view (database-design.md §4.9).
        builder.HasIndex(e => new { e.IncidentId, e.OccurredAt });

        builder.HasOne(e => e.Incident)
            .WithMany()
            .HasForeignKey(e => e.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // ActorUserId is nullable — null for system-generated events.
        builder.HasOne(e => e.ActorUser)
            .WithMany()
            .HasForeignKey(e => e.ActorUserId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
