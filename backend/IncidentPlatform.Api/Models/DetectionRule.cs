namespace IncidentPlatform.Api.Models;

// Imported definitions remain disabled until explicitly reviewed.
public sealed class DetectionRule
{
    public long Id { get; set; }
    public string ExternalRuleId { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "";
    public string? ReferenceTag { get; set; }
    public string DefinitionJson { get; set; } = "{}";
    public bool Enabled { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
