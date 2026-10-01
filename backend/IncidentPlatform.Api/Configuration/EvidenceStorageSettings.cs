using System.ComponentModel.DataAnnotations;

namespace IncidentPlatform.Api.Configuration;

public sealed class EvidenceStorageSettings
{
    public const string SectionName = "EvidenceStorage";

    [Required]
    public string RootPath { get; init; } = string.Empty;

    [Range(1, 500)]
    public int MaxFileSizeMb { get; init; } = 100;
}
