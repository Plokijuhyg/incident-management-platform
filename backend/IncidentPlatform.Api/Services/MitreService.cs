using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Mitre;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

public class MitreService : IMitreService
{
    private readonly AppDbContext _dbContext;
    private readonly ICurrentUser _currentUser;

    public MitreService(AppDbContext dbContext, ICurrentUser currentUser)
    {
        _dbContext = dbContext;
        _currentUser = currentUser;
    }

    public async Task<List<MitreTechniqueResponse>> GetTechniquesAsync(string? tactic, string? search, bool includeSubTechniques, CancellationToken cancellationToken = default)
    {
        var query = _dbContext.MitreTechniques.Where(t => !t.IsDeprecated).AsQueryable();

        if (!string.IsNullOrWhiteSpace(tactic)) query = query.Where(t => t.Tactic == tactic);
        if (!includeSubTechniques) query = query.Where(t => !t.IsSubTechnique);
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(t => t.Name.Contains(search) || t.TechniqueId.Contains(search));

        return await query
            .OrderBy(t => t.TechniqueId)
            .Select(t => ToResponse(t))
            .ToListAsync(cancellationToken);
    }

    public async Task<MitreTechniqueResponse> GetByTechniqueIdAsync(string techniqueId, CancellationToken cancellationToken = default)
    {
        var technique = await _dbContext.MitreTechniques
            .SingleOrDefaultAsync(t => t.TechniqueId == techniqueId, cancellationToken);

        return technique is null
            ? throw new NotFoundException($"MITRE technique '{techniqueId}' was not found.")
            : ToResponse(technique);
    }

    public async Task<List<string>> GetTacticsAsync(CancellationToken cancellationToken = default)
    {
        return await _dbContext.MitreTechniques
            .Where(t => !t.IsDeprecated)
            .Select(t => t.Tactic)
            .Distinct()
            .OrderBy(t => t)
            .ToListAsync(cancellationToken);
    }

    public async Task LinkToIncidentAsync(int incidentId, LinkMitreTechniqueRequest request, CancellationToken cancellationToken = default)
    {
        var incidentExists = await _dbContext.Incidents.AnyAsync(i => i.Id == incidentId, cancellationToken);
        if (!incidentExists) throw new NotFoundException("Incident", incidentId);

        var techniqueExists = await _dbContext.MitreTechniques.AnyAsync(t => t.Id == request.MitreTechniqueId, cancellationToken);
        if (!techniqueExists) throw new NotFoundException("MitreTechnique", request.MitreTechniqueId);

        var alreadyLinked = await _dbContext.IncidentMitreTechniques
            .AnyAsync(imt => imt.IncidentId == incidentId && imt.MitreTechniqueId == request.MitreTechniqueId, cancellationToken);
        if (alreadyLinked) throw new ConflictException("This technique is already linked to this incident.");

        _dbContext.IncidentMitreTechniques.Add(new IncidentMitreTechnique
        {
            IncidentId = incidentId,
            MitreTechniqueId = request.MitreTechniqueId,
            Notes = request.Notes,
            AddedById = _currentUser.Id,
            AddedAt = DateTime.UtcNow
        });

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task UnlinkFromIncidentAsync(int incidentId, int mitreTechniqueId, CancellationToken cancellationToken = default)
    {
        var link = await _dbContext.IncidentMitreTechniques
            .SingleOrDefaultAsync(imt => imt.IncidentId == incidentId && imt.MitreTechniqueId == mitreTechniqueId, cancellationToken)
            ?? throw new NotFoundException("IncidentMitreTechnique link", $"{incidentId}/{mitreTechniqueId}");

        _dbContext.IncidentMitreTechniques.Remove(link);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    private static MitreTechniqueResponse ToResponse(MitreTechnique t) => new()
    {
        Id = t.Id,
        TechniqueId = t.TechniqueId,
        Name = t.Name,
        Description = t.Description,
        Tactic = t.Tactic,
        Url = t.Url,
        ParentTechniqueId = t.ParentTechniqueId,
        IsSubTechnique = t.IsSubTechnique,
        IsDeprecated = t.IsDeprecated
    };
}
