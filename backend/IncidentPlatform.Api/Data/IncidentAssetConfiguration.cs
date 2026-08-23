using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class IncidentAssetConfiguration : IEntityTypeConfiguration<IncidentAsset>
{
    public void Configure(EntityTypeBuilder<IncidentAsset> builder)
    {
        builder.ToTable("IncidentAssets");

        builder.HasKey(ia => new { ia.IncidentId, ia.AssetId });

        builder.Property(ia => ia.ImpactType).HasConversion<string>().HasMaxLength(20).IsRequired();
        builder.Property(ia => ia.Notes).HasMaxLength(500);
        builder.Property(ia => ia.AddedAt).HasColumnType("datetime(6)");

        builder.HasOne(ia => ia.Incident)
            .WithMany()
            .HasForeignKey(ia => ia.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // RESTRICT here is my inference, not an explicit rule in
        // database-design.md §5 (which only states IncidentIocs->Iocs and
        // IncidentMitreTechniques->MitreTechniques explicitly). Applied by
        // the same logic: an asset referenced by incident history shouldn't
        // vanish out from under it. Flagged for your confirmation.
        builder.HasOne(ia => ia.Asset)
            .WithMany()
            .HasForeignKey(ia => ia.AssetId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(ia => ia.AddedBy)
            .WithMany()
            .HasForeignKey(ia => ia.AddedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
