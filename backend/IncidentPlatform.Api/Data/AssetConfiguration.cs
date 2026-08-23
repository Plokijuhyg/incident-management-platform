using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class AssetConfiguration : IEntityTypeConfiguration<Asset>
{
    public void Configure(EntityTypeBuilder<Asset> builder)
    {
        builder.ToTable("Assets");

        builder.HasKey(a => a.Id);

        builder.Property(a => a.Name).HasMaxLength(200).IsRequired();
        builder.Property(a => a.Hostname).HasMaxLength(255);
        builder.Property(a => a.IpAddress).HasMaxLength(45); // max IPv6 text length
        builder.Property(a => a.MacAddress).HasMaxLength(17);
        builder.Property(a => a.OperatingSystem).HasMaxLength(150);
        builder.Property(a => a.Owner).HasMaxLength(150);
        builder.Property(a => a.Department).HasMaxLength(150);
        builder.Property(a => a.Location).HasMaxLength(200);

        // Persisted as strings (architecture.md §5) — a raw 3 in the DB is
        // unreadable, and inserting a new enum member later would silently
        // shift stored integer values for every existing row.
        builder.Property(a => a.Type)
            .HasConversion<string>()
            .HasMaxLength(30)
            .IsRequired();

        builder.Property(a => a.Criticality)
            .HasConversion<string>()
            .HasMaxLength(20)
            .IsRequired();

        builder.Property(a => a.IsActive).HasDefaultValue(true);

        builder.Property(a => a.CreatedAt).HasColumnType("datetime(6)");
        builder.Property(a => a.UpdatedAt).HasColumnType("datetime(6)");

        builder.HasIndex(a => a.Hostname).IsUnique();
        builder.HasIndex(a => a.IsActive);
    }
}
