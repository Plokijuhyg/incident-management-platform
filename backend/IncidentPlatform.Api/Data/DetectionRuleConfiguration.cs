using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace IncidentPlatform.Api.Data;
public sealed class DetectionRuleConfiguration : IEntityTypeConfiguration<DetectionRule>
{
    public void Configure(EntityTypeBuilder<DetectionRule> b)
    {
        b.HasKey(x => x.Id);
        b.Property(x => x.ExternalRuleId).HasMaxLength(36).IsRequired();
        b.HasIndex(x => x.ExternalRuleId).IsUnique();
        b.Property(x => x.Title).HasMaxLength(512).IsRequired();
        b.Property(x => x.Severity).HasMaxLength(20).IsRequired();
        b.Property(x => x.ReferenceTag).HasMaxLength(255);
        b.Property(x => x.DefinitionJson).HasColumnType("json").IsRequired();
        b.Property(x => x.Enabled).HasDefaultValue(false);
        b.HasIndex(x => x.Enabled);
    }
}
