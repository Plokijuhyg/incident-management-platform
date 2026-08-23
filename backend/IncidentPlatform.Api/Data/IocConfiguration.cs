using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IncidentPlatform.Api.Data;

public class IocConfiguration : IEntityTypeConfiguration<Ioc>
{
    public void Configure(EntityTypeBuilder<Ioc> builder)
    {
        builder.ToTable("Iocs");

        builder.HasKey(i => i.Id);

        builder.Property(i => i.Value).HasMaxLength(512).IsRequired();
        builder.Property(i => i.RawValue).HasMaxLength(512);
        builder.Property(i => i.Source).HasMaxLength(100);
        builder.Property(i => i.Description).HasMaxLength(500);

        builder.Property(i => i.Type)
            .HasConversion<string>()
            .HasMaxLength(20)
            .IsRequired();

        builder.Property(i => i.Confidence)
            .HasConversion<string>()
            .HasMaxLength(20)
            .IsRequired();

        // IsMalicious stays a plain nullable bool -> tinyint(1) NULL. No
        // HasConversion needed; only enums get the string-conversion
        // treatment.

        builder.Property(i => i.FirstSeenAt).HasColumnType("datetime(6)");
        builder.Property(i => i.LastSeenAt).HasColumnType("datetime(6)");
        builder.Property(i => i.CreatedAt).HasColumnType("datetime(6)");
        builder.Property(i => i.UpdatedAt).HasColumnType("datetime(6)");

        builder.Property(i => i.SightingCount).HasDefaultValue(0);

        // The deduplication guarantee itself (database-design.md §3.1).
        // Composite because the same string can legitimately be two types.
        builder.HasIndex(i => new { i.Type, i.Value }).IsUnique();

        // CreatedBy -> Users: RESTRICT, per the blanket "Any -> Users:
        // RESTRICT" policy in database-design.md §5. Users are deactivated,
        // never deleted, so this path should realistically never fire.
        builder.HasOne(i => i.CreatedBy)
            .WithMany()
            .HasForeignKey(i => i.CreatedById)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
