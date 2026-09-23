using IncidentPlatform.Api.DTOs.Mitre;

namespace IncidentPlatform.Api.Interfaces;

public interface IMitreService
{
    Task<List<MitreTechniqueResponse>> GetTechniquesAsync(string? tactic, string? search, bool includeSubTechniques, CancellationToken cancellationToken = default);

    Task<MitreTechniqueResponse> GetByTechniqueIdAsync(string techniqueId, CancellationToken cancellationToken = default);

    Task<List<string>> GetTacticsAsync(CancellationToken cancellationToken = default);

    Task LinkToIncidentAsync(int incidentId, LinkMitreTechniqueRequest request, CancellationToken cancellationToken = default);

    Task UnlinkFromIncidentAsync(int incidentId, int mitreTechniqueId, CancellationToken cancellationToken = default);
}
