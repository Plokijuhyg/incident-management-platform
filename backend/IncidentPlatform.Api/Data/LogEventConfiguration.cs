using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public sealed class LogEventConfiguration : IEntityTypeConfiguration<LogEvent>
{
    public void Configure(EntityTypeBuilder<LogEvent> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.Fingerprint).HasMaxLength(64);
        b.HasIndex(x => x.Fingerprint).IsUnique();

        b.Property(x => x.Source).HasMaxLength(100);
        b.Property(x => x.SourceType).HasConversion<string>().HasMaxLength(20);
        b.Property(x => x.Host).HasMaxLength(255);
        b.Property(x => x.Facility).HasMaxLength(32);
        b.Property(x => x.Action).HasMaxLength(64);
        b.Property(x => x.Outcome).HasMaxLength(32);
        b.Property(x => x.SourceIp).HasMaxLength(45);
        b.Property(x => x.DestinationIp).HasMaxLength(45);
        b.Property(x => x.Protocol).HasMaxLength(16);
        b.Property(x => x.User).HasMaxLength(255);
        b.Property(x => x.Message).HasColumnType("longtext");
        b.Property(x => x.RawLog).HasColumnType("longtext");
        b.Property(x => x.FieldsJson).HasColumnType("json");
        b.Property(x => x.EnrichmentJson).HasColumnType("json");

        // The timeline view pages by EventTime; the others back the queue filters.
        b.HasIndex(x => x.EventTime);
        b.HasIndex(x => x.ReceivedAt);
        b.HasIndex(x => new { x.Source, x.Id });
        b.HasIndex(x => new { x.SourceType, x.Id });
        b.HasIndex(x => x.SourceIp);
        b.HasIndex(x => x.DestinationIp);

        b.HasOne<Alert>().WithMany().HasForeignKey(x => x.AlertId).OnDelete(DeleteBehavior.SetNull);
    }
}
