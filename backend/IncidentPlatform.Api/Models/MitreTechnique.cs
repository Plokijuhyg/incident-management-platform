namespace IncidentPlatform.Api.Models;

/// <summary>
/// Seeded reference data, not user content (database-design.md §4.7). The
/// surrogate Id is the FK target for the join table, not TechniqueId itself
/// — so a MITRE re-identification never cascades through IncidentMitreTechniques.
/// Self-referencing FK models sub-techniques (T1059.001 under T1059).
/// </summary>
public class MitreTechnique
{
    public int Id { get; set; }
    public string TechniqueId { get; set; } = string.Empty; // e.g. "T1059", "T1059.001"
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Tactic { get; set; } = string.Empty; // e.g. "Execution"
    public string? Url { get; set; }

    public int? ParentTechniqueId { get; set; }
    public MitreTechnique? ParentTechnique { get; set; }

    public bool IsSubTechnique { get; set; }
    public bool IsDeprecated { get; set; }
}
