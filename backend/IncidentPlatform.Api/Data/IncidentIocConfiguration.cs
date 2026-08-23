using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class IncidentIocConfiguration : IEntityTypeConfiguration<IncidentIoc>
{
    public void Configure(EntityTypeBuilder<IncidentIoc> builder)
    {
        builder.ToTable("IncidentIocs");

        builder.HasKey(ii => new { ii.IncidentId, ii.IocId });

        builder.Property(ii => ii.Role).HasConversion<string>().HasMaxLength(20).IsRequired();
        builder.Property(ii => ii.Notes).HasMaxLength(500);
        builder.Property(ii => ii.AddedAt).HasColumnType("datetime(6)");

        // CASCADE: a link cannot outlive its incident (database-design.md §5).
        builder.HasOne(ii => ii.Incident)
            .WithMany()
            .HasForeignKey(ii => ii.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // RESTRICT: the catalog entry is shared across incidents — deleting
        // it here would rewrite other incidents' history (database-design.md §5).
        builder.HasOne(ii => ii.Ioc)
            .WithMany()
            .HasForeignKey(ii => ii.IocId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(ii => ii.AddedBy)
            .WithMany()
            .HasForeignKey(ii => ii.AddedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
