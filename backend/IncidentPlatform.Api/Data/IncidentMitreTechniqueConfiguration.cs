using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class IncidentMitreTechniqueConfiguration : IEntityTypeConfiguration<IncidentMitreTechnique>
{
    public void Configure(EntityTypeBuilder<IncidentMitreTechnique> builder)
    {
        builder.ToTable("IncidentMitreTechniques");

        builder.HasKey(imt => new { imt.IncidentId, imt.MitreTechniqueId });

        builder.Property(imt => imt.Notes).HasMaxLength(500);
        builder.Property(imt => imt.AddedAt).HasColumnType("datetime(6)");

        builder.HasOne(imt => imt.Incident)
            .WithMany()
            .HasForeignKey(imt => imt.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // RESTRICT: reference data, deprecate via IsDeprecated instead of
        // delete (database-design.md §5, explicitly stated for this pair).
        builder.HasOne(imt => imt.MitreTechnique)
            .WithMany()
            .HasForeignKey(imt => imt.MitreTechniqueId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(imt => imt.AddedBy)
            .WithMany()
            .HasForeignKey(imt => imt.AddedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
