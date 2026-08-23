namespace IncidentPlatform.Api.Models;

public enum ImpactType
{
    Compromised,
    Suspected,
    Targeted,
    Affected,
    PatientZero
}

/// <summary>
/// PatientZero is modelled explicitly (database-design.md §4.6) — "where did
/// this start" is the first question in every real investigation.
/// </summary>
public class IncidentAsset
{
    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    public int AssetId { get; set; }
    public Asset Asset { get; set; } = null!;

    public ImpactType ImpactType { get; set; }
    public string? Notes { get; set; }

    public int AddedById { get; set; }
    public User AddedBy { get; set; } = null!;

    public DateTime AddedAt { get; set; }
}

