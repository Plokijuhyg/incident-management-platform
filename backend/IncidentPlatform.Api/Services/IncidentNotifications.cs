using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using MySqlConnector;
namespace IncidentPlatform.Api.Services;

public sealed record NotificationSettings(bool Enabled,string Host,int Port,string From,string[] To,string? Username,string? Password,Uri? AppUrl,DateTime StartAfter,IncidentSeverity Threshold,string[] Missing)
{
 public bool Ready=>Enabled && Missing.Length==0;
 public static NotificationSettings Read(IConfiguration c)
 {
  var errors=new List<string>();var enabled=c.GetValue<bool>("Notifications:Enabled");
  var host=c["Notifications:Smtp:Host"]??"";var from=c["Notifications:Smtp:From"]??"";var to=c.GetSection("Notifications:Smtp:To").Get<string[]>()??[];
  var port=c.GetValue<int?>("Notifications:Smtp:Port")??587;var username=c["Notifications:Smtp:Username"];var password=c["Notifications:Smtp:Password"];
  if(string.IsNullOrWhiteSpace(host))errors.Add("Notifications:Smtp:Host");if(port is <1 or >65535 || port==465)errors.Add("Notifications:Smtp:Port (STARTTLS port, normally 587)");
  if(!MailAddress.TryCreate(from,out _))errors.Add("Notifications:Smtp:From");if(to.Length is <1 or >20 || to.Any(x=>!MailAddress.TryCreate(x,out _)))errors.Add("Notifications:Smtp:To");
  if(!string.IsNullOrWhiteSpace(username)&&string.IsNullOrWhiteSpace(password))errors.Add("Notifications:Smtp:Password");
  Uri.TryCreate(c["Notifications:AppBaseUrl"],UriKind.Absolute,out var app);
  if(app is null || !(app.Scheme=="https" || app.Scheme=="http"&&app.IsLoopback) || app.UserInfo!="" || app.Query!="" || app.Fragment!="")errors.Add("Notifications:AppBaseUrl");
  var since=c["Notifications:StartAfterUtc"];
  if(!DateTimeOffset.TryParse(since,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal,out var start))errors.Add("Notifications:StartAfterUtc");
  if(!Enum.TryParse<IncidentSeverity>(c["Notifications:MinimumSeverity"]??"High",true,out var threshold)||!Enum.IsDefined(threshold))errors.Add("Notifications:MinimumSeverity");
  return new(enabled,host,port,from,to,username,password,app,start.UtcDateTime,threshold,errors.ToArray());
 }
}
public interface IIncidentEmailSender {Task Send(NotificationSettings settings,string subject,string body,CancellationToken ct);}
public sealed class SmtpIncidentEmailSender:IIncidentEmailSender
{
 public async Task Send(NotificationSettings s,string subject,string body,CancellationToken ct)
 {
  using var smtp=new SmtpClient(s.Host,s.Port){EnableSsl=true,UseDefaultCredentials=false};
  if(!string.IsNullOrWhiteSpace(s.Username))smtp.Credentials=new NetworkCredential(s.Username,s.Password);
  using var message=new MailMessage{From=new MailAddress(s.From),Subject=subject,Body=body,IsBodyHtml=false,BodyEncoding=Encoding.UTF8,SubjectEncoding=Encoding.UTF8};
  foreach(var recipient in s.To)message.To.Add(recipient);
  using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(10));
  await smtp.SendMailAsync(message,timeout.Token);
 }
}
public sealed class IncidentNotificationProcessor(AppDbContext db,IConfiguration config,IIncidentEmailSender sender)
{
 public static (string subject,string body) Content(Incident i,IEnumerable<string> targets,Uri app)
 {
  var title=i.Title.Replace('\r',' ').Replace('\n',' ');var names=string.Join(", ",targets.Take(10));if(names.Length==0)names="Not linked";
  return ($"[{i.Severity}] {i.IncidentNumber}: {title}",$"Incident: {title}\nSeverity: {i.Severity}\nAffected target: {names}\nOpen: {app.ToString().TrimEnd('/')}/incidents/{i.Id}\n\nReview required. No response action was executed.");
 }
 public async Task Run(CancellationToken ct)
 {
  var s=NotificationSettings.Read(config);if(!s.Ready)return;
  await db.Database.OpenConnectionAsync(ct);var connection=(MySqlConnection)db.Database.GetDbConnection();
  var key="notify:"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(connection.Database)))[..40];
  await using var guard=new MySqlCommand("SELECT GET_LOCK(@key,0)",connection);guard.Parameters.AddWithValue("@key",key);if(Convert.ToInt32(await guard.ExecuteScalarAsync(ct))!=1)return;
  try
  {
   var now=DateTime.UtcNow;
   var ids=await db.Incidents.Where(i=>i.CreatedAt>=s.StartAfter && (int)i.Severity>=(int)s.Threshold && !db.IncidentNotifications.Any(n=>n.IncidentId==i.Id)).OrderBy(i=>i.Id).Take(25).Select(i=>i.Id).ToListAsync(ct);
   foreach(var id in ids)db.IncidentNotifications.Add(new(){IncidentId=id,CreatedAt=now,NextAttemptAt=now});await db.SaveChangesAsync(ct);
   var pending=await db.IncidentNotifications.Include(n=>n.Incident).Where(n=>n.State=="Pending" && n.NextAttemptAt<=now && n.Incident.CreatedAt>=s.StartAfter && (int)n.Incident.Severity>=(int)s.Threshold).OrderBy(n=>n.NextAttemptAt).Take(10).ToListAsync(ct);
   foreach(var row in pending)
   {
    if((int)row.Incident.Severity<(int)s.Threshold || row.Incident.CreatedAt<s.StartAfter)continue;
    var targets=await db.IncidentAssets.Where(a=>a.IncidentId==row.IncidentId).Select(a=>a.Asset.Name).ToListAsync(ct);var content=Content(row.Incident,targets,s.AppUrl!);
    row.Attempts++;
    try{await sender.Send(s,content.subject,content.body,ct);row.State="Sent";row.SentAt=DateTime.UtcNow;row.LastError=null;}
    catch(Exception ex) when(ex is SmtpException or HttpRequestException or OperationCanceledException or InvalidOperationException)
    {if(ct.IsCancellationRequested)throw;row.LastError=ex.GetType().Name;row.State=row.Attempts>=3?"Failed":"Pending";row.NextAttemptAt=DateTime.UtcNow.AddMinutes(Math.Pow(2,row.Attempts-1));}
    db.AuditLogs.Add(new(){Action=row.State=="Sent"?"INCIDENT_EMAIL_SENT":"INCIDENT_EMAIL_FAILED",EntityType="Incident",EntityId=row.IncidentId.ToString(),ActorEmail="system:notifications",OccurredAt=DateTime.UtcNow,Outcome=row.State=="Sent"?AuditOutcome.Success:AuditOutcome.Failure,Details=System.Text.Json.JsonSerializer.Serialize(new{row.Attempts,row.State,row.LastError})});
    await db.SaveChangesAsync(ct);
   }
  }
  finally{await using var release=new MySqlCommand("SELECT RELEASE_LOCK(@key)",connection);release.Parameters.AddWithValue("@key",key);await release.ExecuteScalarAsync(CancellationToken.None);}
 }
}
public sealed class IncidentNotificationWorker(IServiceScopeFactory scopes,IHostEnvironment environment,ILogger<IncidentNotificationWorker> logger):BackgroundService
{
 protected override async Task ExecuteAsync(CancellationToken ct)
 {
  if(environment.IsEnvironment("Testing"))return;
  while(!ct.IsCancellationRequested)
  {
   try{using var scope=scopes.CreateScope();await scope.ServiceProvider.GetRequiredService<IncidentNotificationProcessor>().Run(ct);}
   catch(OperationCanceledException) when(ct.IsCancellationRequested){break;}
   catch(Exception ex){logger.LogWarning("Notification cycle failed ({ErrorType}); incident creation is unaffected.",ex.GetType().Name);}
   try{await Task.Delay(TimeSpan.FromSeconds(15),ct);}catch(OperationCanceledException){break;}
  }
 }
}
