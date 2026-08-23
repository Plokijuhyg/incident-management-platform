using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class EvidenceConfiguration : IEntityTypeConfiguration<Evidence>
{
    public void Configure(EntityTypeBuilder<Evidence> builder)
    {
        builder.ToTable("Evidence");

        builder.HasKey(e => e.Id);

        builder.Property(e => e.OriginalFileName).HasMaxLength(255).IsRequired();
        builder.Property(e => e.StoredFileName).HasMaxLength(100).IsRequired();
        builder.Property(e => e.ContentType).HasMaxLength(100).IsRequired();
        builder.Property(e => e.Sha256).HasMaxLength(64).IsFixedLength().IsRequired();
        builder.Property(e => e.Description).HasMaxLength(500);

        builder.Property(e => e.EvidenceType).HasConversion<string>().HasMaxLength(30).IsRequired();
        builder.Property(e => e.StorageProvider).HasConversion<string>().HasMaxLength(20).IsRequired();

        builder.Property(e => e.UploadedAt).HasColumnType("datetime(6)");

        builder.HasIndex(e => e.IncidentId);
        builder.HasIndex(e => e.Sha256);

        builder.HasOne(e => e.Incident)
            .WithMany()
            .HasForeignKey(e => e.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(e => e.UploadedBy)
            .WithMany()
            .HasForeignKey(e => e.UploadedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
