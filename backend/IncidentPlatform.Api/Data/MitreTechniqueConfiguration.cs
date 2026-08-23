using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class MitreTechniqueConfiguration : IEntityTypeConfiguration<MitreTechnique>
{
    public void Configure(EntityTypeBuilder<MitreTechnique> builder)
    {
        builder.ToTable("MitreTechniques");

        builder.HasKey(m => m.Id);

        builder.Property(m => m.TechniqueId).HasMaxLength(20).IsRequired();
        builder.Property(m => m.Name).HasMaxLength(200).IsRequired();
        builder.Property(m => m.Description).HasColumnType("text");
        builder.Property(m => m.Tactic).HasMaxLength(50).IsRequired();
        builder.Property(m => m.Url).HasMaxLength(500);

        builder.HasIndex(m => m.TechniqueId).IsUnique();
        builder.HasIndex(m => m.Tactic);

        // Self-referencing, nullable FK for sub-techniques (T1059.001 under
        // T1059). RESTRICT: a parent technique is reference data and must
        // not vanish out from under its children — deprecate via
        // IsDeprecated instead of deleting (database-design.md §4.7).
        builder.HasOne(m => m.ParentTechnique)
            .WithMany()
            .HasForeignKey(m => m.ParentTechniqueId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
