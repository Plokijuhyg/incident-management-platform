using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace IncidentPlatform.Api.Data;
public sealed class AutomationRuleConfiguration : IEntityTypeConfiguration<AutomationRule>
{
    public void Configure(EntityTypeBuilder<AutomationRule> b)
    {
        b.HasKey(x=>x.Id); b.Property(x=>x.Id).HasMaxLength(80);
        b.Property(x=>x.Mode).HasMaxLength(20); b.Property(x=>x.Version).IsConcurrencyToken();
        b.HasOne<User>().WithMany().HasForeignKey(x=>x.OwnerId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<User>().WithMany().HasForeignKey(x=>x.ApprovedById).OnDelete(DeleteBehavior.Restrict);
        foreach(var id in new[]{"WIN-DEFENDER-DETECTION","WIN-AUDIT-CLEARED","WIN-ACCOUNT-CREATED","WIN-LOCAL-GROUP-MEMBER"})
            b.HasData(new AutomationRule{Id=id,EffectiveFrom=new DateTime(2026,9,26,0,0,0,DateTimeKind.Utc),UpdatedAt=new DateTime(2026,9,26,0,0,0,DateTimeKind.Utc)});
    }
}
public sealed class AutomationDecisionConfiguration : IEntityTypeConfiguration<AutomationDecision>
{
    public void Configure(EntityTypeBuilder<AutomationDecision> b)
    {
        b.HasKey(x=>x.Id); b.HasIndex(x=>x.AlertId).IsUnique();
        b.Property(x=>x.RuleId).HasMaxLength(80); b.Property(x=>x.Machine).HasMaxLength(255);
        b.Property(x=>x.Outcome).HasMaxLength(40); b.Property(x=>x.Reason).HasMaxLength(1024);
        b.Property(x=>x.PolicySnapshot).HasColumnType("json");
        b.HasIndex(x=>new{x.RuleId,x.Machine,x.CreatedAt});
        b.HasOne<Alert>().WithMany().HasForeignKey(x=>x.AlertId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<Incident>().WithMany().HasForeignKey(x=>x.IncidentId).OnDelete(DeleteBehavior.SetNull);
        b.HasOne<AutomationRule>().WithMany().HasForeignKey(x=>x.RuleId).OnDelete(DeleteBehavior.Restrict);
    }
}
