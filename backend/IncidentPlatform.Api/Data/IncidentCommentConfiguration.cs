using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class IncidentCommentConfiguration : IEntityTypeConfiguration<IncidentComment>
{
    public void Configure(EntityTypeBuilder<IncidentComment> builder)
    {
        builder.ToTable("IncidentComments");

        builder.HasKey(c => c.Id);

        builder.Property(c => c.Body).HasColumnType("text").IsRequired();
        builder.Property(c => c.IsInternal).HasDefaultValue(false);

        builder.Property(c => c.CreatedAt).HasColumnType("datetime(6)");
        builder.Property(c => c.UpdatedAt).HasColumnType("datetime(6)");
        builder.Property(c => c.EditedAt).HasColumnType("datetime(6)");

        builder.HasIndex(c => new { c.IncidentId, c.CreatedAt });

        builder.HasOne(c => c.Incident)
            .WithMany()
            .HasForeignKey(c => c.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(c => c.Author)
            .WithMany()
            .HasForeignKey(c => c.AuthorId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
