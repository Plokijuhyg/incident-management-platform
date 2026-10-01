using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Services;
public sealed class AssessmentService(AppDbContext db,AssessmentGateway gateway,ICurrentUser user,IAuditContext audit)
{
 public async Task<SecurityAssessment> Create(string targetId,string profile,CancellationToken ct)
 {
  if(!gateway.Enabled)throw new ValidationAppException("Configure Laptop 2 before starting an assessment.");
  var target=gateway.Targets.SingleOrDefault(x=>x.Id==targetId&&x.Approved);
  if(target is null||!AssessmentGateway.PrivateIp(target.Ip))throw new ValidationAppException("Target must be an approved private lab IP.");
  if(profile is not ("tcp-services" or "vulnerability-checks"))throw new ValidationAppException("Select a supported inventory or vulnerability-checks profile.");
  if(await db.SecurityAssessments.CountAsync(x=>x.Status=="Pending"||x.Status=="Running",ct)>=10)throw new ValidationAppException("Assessment queue is full.");
  var row=new SecurityAssessment{RequestedById=user.Id,TargetId=target.Id,TargetName=target.Name,TargetIp=target.Ip,Profile=profile};db.Add(row);await db.SaveChangesAsync(ct);return row;
 }
 public async Task<SecurityAssessment> CreateSelection(string targetId,string selection,CancellationToken ct)
 {
  if(!gateway.Enabled)throw new ValidationAppException("HexStrike disabled.");
  var target=gateway.FindTarget(targetId);
  if(target is null)throw new ValidationAppException("Target approval changed.");
  if(await db.SecurityAssessments.CountAsync(x=>x.Status=="Pending"||x.Status=="Running",ct)>=10)throw new ValidationAppException("Assessment queue is full.");
  var row=new SecurityAssessment{RequestedById=user.Id,TargetId=target.Id,TargetName=target.Name,TargetIp=target.Ip,Profile="selected-tools",RequestJson=selection};
  db.Add(row);db.AuditLogs.Add(audit.Create("ASSESSMENT_REQUESTED","SecurityAssessment",row.Id,details:selection));await db.SaveChangesAsync(ct);return row;
 }
 public async Task<SecurityAssessment> Get(string id,CancellationToken ct)=>await db.SecurityAssessments.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw new NotFoundException("Assessment",id);
 public async Task Cancel(string id,CancellationToken ct)
 {
  await using var transaction=await db.Database.BeginTransactionAsync(ct);
  var affected=await db.SecurityAssessments.Where(x=>x.Id==id&&x.Status=="Pending").ExecuteUpdateAsync(u=>u.SetProperty(x=>x.Status,"Cancelled").SetProperty(x=>x.FinishedAt,DateTime.UtcNow),ct);
  if(affected==0)throw new ConflictException("Only queued assessments can be cancelled. Dispatched tools require confirmed remote termination; cancellation is not claimed.");
  db.AuditLogs.Add(audit.Create("ASSESSMENT_CANCELLED","SecurityAssessment",id));await db.SaveChangesAsync(ct);await transaction.CommitAsync(ct);
 }
}
