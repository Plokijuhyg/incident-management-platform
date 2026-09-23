namespace IncidentPlatform.Api.DTOs.Mitre;

public class MitreTechniqueResponse
{
    public int Id { get; set; }
    public string TechniqueId { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Tactic { get; set; } = string.Empty;
    public string? Url { get; set; }
    public int? ParentTechniqueId { get; set; }
    public bool IsSubTechnique { get; set; }
    public bool IsDeprecated { get; set; }
}

public class LinkMitreTechniqueRequest
{
    public int MitreTechniqueId { get; set; }
    public string? Notes { get; set; }
}
