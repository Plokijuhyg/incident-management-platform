namespace IncidentPlatform.Api.Models;
// Delivery state only; the existing Incident remains the source of incident data.
public sealed class IncidentNotification
{
    public int IncidentId {get;set;}
    public Incident Incident {get;set;}=null!;
    public string State {get;set;}="Pending";
    public int Attempts {get;set;}
    public DateTime CreatedAt {get;set;}
    public DateTime NextAttemptAt {get;set;}
    public DateTime? SentAt {get;set;}
    public string? LastError {get;set;}
}
