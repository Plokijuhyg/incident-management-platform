using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace IncidentPlatform.Api.Data;
public sealed class WindowsEventConfiguration : IEntityTypeConfiguration<WindowsEvent>
{
    public void Configure(EntityTypeBuilder<WindowsEvent> b)
    {
        b.HasKey(x=>x.Id);
        b.Property(x=>x.Fingerprint).HasMaxLength(64);b.HasIndex(x=>x.Fingerprint).IsUnique();
        b.Property(x=>x.Machine).HasMaxLength(255);b.Property(x=>x.Channel).HasMaxLength(255);b.Property(x=>x.Provider).HasMaxLength(255);
        b.Property(x=>x.RawXml).HasColumnType("longtext");b.Property(x=>x.Message).HasColumnType("longtext");
        b.HasIndex(x=>new{x.Channel,x.Id});b.HasIndex(x=>new{x.EventId,x.Id});b.HasIndex(x=>x.ReceivedAt);
        b.HasOne<Alert>().WithMany().HasForeignKey(x=>x.AlertId).OnDelete(DeleteBehavior.SetNull);
    }
}
public sealed class WindowsEventCheckpointConfiguration : IEntityTypeConfiguration<WindowsEventCheckpoint>
{
    public void Configure(EntityTypeBuilder<WindowsEventCheckpoint> b)
    {
        b.HasKey(x=>x.Id);b.Property(x=>x.Machine).HasMaxLength(255);b.Property(x=>x.Channel).HasMaxLength(255);
        b.HasIndex(x=>new{x.Machine,x.Channel}).IsUnique();b.Property(x=>x.Bookmark).HasColumnType("longtext");b.Property(x=>x.Error).HasMaxLength(1024);
    }
}
