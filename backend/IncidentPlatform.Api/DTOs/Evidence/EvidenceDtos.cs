using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.DTOs.Evidence;

public class EvidenceResponse
{
    public int Id { get; set; }
    public string OriginalFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public EvidenceType EvidenceType { get; set; }
    public string? Description { get; set; }
    public string UploadedByName { get; set; } = string.Empty;
    public DateTime UploadedAt { get; set; }
}
