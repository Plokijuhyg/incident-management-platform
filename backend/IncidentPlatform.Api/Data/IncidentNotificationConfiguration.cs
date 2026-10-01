using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
namespace IncidentPlatform.Api.Data;
public sealed class IncidentNotificationConfiguration:IEntityTypeConfiguration<IncidentNotification>
{
 public void Configure(EntityTypeBuilder<IncidentNotification> b){b.HasKey(x=>x.IncidentId);b.Property(x=>x.IncidentId).ValueGeneratedNever();b.HasOne(x=>x.Incident).WithMany().HasForeignKey(x=>x.IncidentId).OnDelete(DeleteBehavior.Cascade);b.Property(x=>x.State).HasMaxLength(20);b.Property(x=>x.LastError).HasMaxLength(100);b.HasIndex(x=>new{x.State,x.NextAttemptAt});}
}
