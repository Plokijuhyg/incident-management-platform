using IncidentPlatform.Api.DTOs.Evidence;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Interfaces;

public interface IEvidenceService
{
    Task<List<EvidenceResponse>> GetForIncidentAsync(int incidentId, CancellationToken cancellationToken = default);

    Task<EvidenceResponse> UploadAsync(int incidentId, Stream fileStream, string originalFileName, string contentType, long sizeBytes, EvidenceType evidenceType, string? description, CancellationToken cancellationToken = default);

    Task<(Stream Stream, string ContentType, string FileName)> DownloadAsync(int incidentId, int evidenceId, CancellationToken cancellationToken = default);

    Task DeleteAsync(int incidentId, int evidenceId, CancellationToken cancellationToken = default);
}
