namespace IncidentPlatform.Api.Models;
public sealed class AutomationRule
{
    public string Id { get; set; } = "";
    public string Mode { get; set; } = "Observe";
    public int Version { get; set; } = 1;
    public int CorrelationMinutes { get; set; } = 60;
    public int? OwnerId { get; set; }
    public int? ApprovedById { get; set; }
    public DateTime EffectiveFrom { get; set; }
    public DateTime UpdatedAt { get; set; }
}
public sealed class AutomationDecision
{
    public long Id { get; set; }
    public int AlertId { get; set; }
    public int? IncidentId { get; set; }
    public string RuleId { get; set; } = "";
    public int PolicyVersion { get; set; }
    public string Machine { get; set; } = "";
    public string Outcome { get; set; } = "";
    public string Reason { get; set; } = "";
    public string PolicySnapshot { get; set; } = "";
    public DateTime CreatedAt { get; set; }
}
