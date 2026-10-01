using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace IncidentPlatform.Api.Data;
public sealed class SecurityAssessmentConfiguration : IEntityTypeConfiguration<SecurityAssessment>
{
 public void Configure(EntityTypeBuilder<SecurityAssessment> b)
 {
  b.Property(x=>x.AnalysisJson).HasColumnType("json");
  b.Property(x=>x.RequestJson).HasColumnType("json");b.HasKey(x=>x.Id);b.Property(x=>x.Id).HasMaxLength(36);b.Property(x=>x.TargetId).HasMaxLength(100);b.Property(x=>x.TargetName).HasMaxLength(200);b.Property(x=>x.TargetIp).HasMaxLength(45);b.Property(x=>x.Profile).HasMaxLength(100);b.Property(x=>x.Status).HasMaxLength(30);b.Property(x=>x.Error).HasMaxLength(1000);b.Property(x=>x.EvidenceSha256).HasMaxLength(64);b.Property(x=>x.RawResponse).HasColumnType("longtext");b.Property(x=>x.ObservationsJson).HasColumnType("json");b.HasIndex(x=>new{x.Status,x.RequestedAt});b.HasOne<User>().WithMany().HasForeignKey(x=>x.RequestedById).OnDelete(DeleteBehavior.Restrict);
 }
}
