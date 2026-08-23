using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class ResponseActionConfiguration : IEntityTypeConfiguration<ResponseAction>
{
    public void Configure(EntityTypeBuilder<ResponseAction> builder)
    {
        builder.ToTable("ResponseActions");

        builder.HasKey(r => r.Id);

        builder.Property(r => r.ActionType).HasConversion<string>().HasMaxLength(40).IsRequired();
        builder.Property(r => r.Description).HasColumnType("text").IsRequired();

        builder.Property(r => r.TargetType).HasConversion<string>().HasMaxLength(20);
        builder.Property(r => r.TargetValue).HasMaxLength(255);

        builder.Property(r => r.Status).HasConversion<string>().HasMaxLength(20).IsRequired();
        builder.Property(r => r.Result).HasColumnType("text");

        builder.Property(r => r.PlannedAt).HasColumnType("datetime(6)");
        builder.Property(r => r.PerformedAt).HasColumnType("datetime(6)");
        builder.Property(r => r.CompletedAt).HasColumnType("datetime(6)");

        builder.HasIndex(r => r.IncidentId);
        builder.HasIndex(r => r.Status);

        builder.HasOne(r => r.Incident)
            .WithMany()
            .HasForeignKey(r => r.IncidentId)
            .OnDelete(DeleteBehavior.Cascade);

        // TargetAssetId is a *third* relationship in this entity (alongside
        // Incident and PerformedBy) — but unlike UserRole/Incident's
        // two-FKs-to-the-same-table situation, this is a FK to a different
        // entity (Assets), so EF Core can infer it without ambiguity. Still
        // configured explicitly for consistency and to set RESTRICT rather
        // than accept EF Core's own default.
        builder.HasOne(r => r.TargetAsset)
            .WithMany()
            .HasForeignKey(r => r.TargetAssetId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(r => r.PerformedBy)
            .WithMany()
            .HasForeignKey(r => r.PerformedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
