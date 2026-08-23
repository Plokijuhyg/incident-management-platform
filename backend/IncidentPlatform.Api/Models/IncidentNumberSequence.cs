namespace IncidentPlatform.Api.Models;

/// <summary>
/// One row per year, incremented under a row lock inside the same
/// transaction that inserts an Incident (database-design.md §3.3). This
/// table exists purely to make that increment race-safe — the actual
/// SELECT ... FOR UPDATE logic lives in IncidentService (Phase 5), not here.
/// </summary>
public class IncidentNumberSequence
{
    public int Year { get; set; }
    public int LastValue { get; set; }
    public DateTime UpdatedAt { get; set; }
}
