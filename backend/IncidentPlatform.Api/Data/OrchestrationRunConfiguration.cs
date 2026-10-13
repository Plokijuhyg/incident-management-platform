using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace IncidentPlatform.Api.Data;
public sealed class OrchestrationRunConfiguration : IEntityTypeConfiguration<OrchestrationRun>
{
 public void Configure(EntityTypeBuilder<OrchestrationRun> b)
 {
  b.HasKey(x=>x.Id);b.Property(x=>x.Id).HasMaxLength(36);
  b.Property(x=>x.Task).HasMaxLength(2000);
  b.Property(x=>x.TargetId).HasMaxLength(100);b.Property(x=>x.TargetName).HasMaxLength(200);b.Property(x=>x.TargetIp).HasMaxLength(45);
  b.Property(x=>x.WebPath).HasMaxLength(200);
  b.Property(x=>x.Status).HasMaxLength(30);b.Property(x=>x.Model).HasMaxLength(100);
  b.Property(x=>x.Error).HasMaxLength(1000);
  b.Property(x=>x.Summary).HasColumnType("longtext");
  b.Property(x=>x.TranscriptJson).HasColumnType("json");
  b.HasIndex(x=>new{x.Status,x.CreatedAt});
  b.HasOne<User>().WithMany().HasForeignKey(x=>x.RequestedById).OnDelete(DeleteBehavior.Restrict);
 }
}
