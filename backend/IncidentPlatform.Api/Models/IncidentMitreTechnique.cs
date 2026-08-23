namespace IncidentPlatform.Api.Models;

/// <summary>
/// Notes describes how the technique manifested in this specific incident
/// (database-design.md §4.7) — the technique itself is reference data,
/// shared across every incident that maps to it.
/// </summary>
public class IncidentMitreTechnique
{
    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    public int MitreTechniqueId { get; set; }
    public MitreTechnique MitreTechnique { get; set; } = null!;

    public string? Notes { get; set; }

    public int AddedById { get; set; }
    public User AddedBy { get; set; } = null!;

    public DateTime AddedAt { get; set; }
}
