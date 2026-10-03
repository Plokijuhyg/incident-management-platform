using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public sealed class EntityProfileConfiguration : IEntityTypeConfiguration<EntityProfile>
{
    public void Configure(EntityTypeBuilder<EntityProfile> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.EntityType).HasMaxLength(16).IsRequired();
        b.Property(x => x.EntityValue).HasMaxLength(255).IsRequired();
        b.HasIndex(x => new { x.EntityType, x.EntityValue }).IsUnique();
        b.Property(x => x.KnownSourceIpsJson).HasColumnType("json");
        b.Property(x => x.LastAnomaly).HasMaxLength(255);
        b.Property(x => x.FirstSeenAt).HasColumnType("datetime(6)");
        b.Property(x => x.LastSeenAt).HasColumnType("datetime(6)");
        b.Property(x => x.WindowStart).HasColumnType("datetime(6)");
        b.Property(x => x.LastAnomalyAt).HasColumnType("datetime(6)");
        b.Property(x => x.UpdatedAt).HasColumnType("datetime(6)");
        b.HasIndex(x => x.RiskScore);
    }
}
