using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.DTOs.Assets;

public class AssetResponse
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Hostname { get; set; }
    public string? IpAddress { get; set; }
    public AssetType Type { get; set; }
    public string? OperatingSystem { get; set; }
    public AssetCriticality Criticality { get; set; }
    public string? Owner { get; set; }
    public string? Department { get; set; }
    public bool IsActive { get; set; }
}

public class AssetDetailResponse : AssetResponse
{
    public List<AssetIncidentAppearance> Incidents { get; set; } = [];
}

public class AssetIncidentAppearance
{
    public int IncidentId { get; set; }
    public string IncidentNumber { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public ImpactType ImpactType { get; set; }
    public DateTime AddedAt { get; set; }
}

public class AssetCreateRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Hostname { get; set; }
    public string? IpAddress { get; set; }
    public string? MacAddress { get; set; }
    public AssetType Type { get; set; }
    public string? OperatingSystem { get; set; }
    public AssetCriticality Criticality { get; set; }
    public string? Owner { get; set; }
    public string? Department { get; set; }
    public string? Location { get; set; }
}

public class AssetUpdateRequest
{
    public string Name { get; set; } = string.Empty;
    public AssetCriticality Criticality { get; set; }
    public string? Owner { get; set; }
    public string? Department { get; set; }
    public bool IsActive { get; set; }
}

public class LinkAssetToIncidentRequest
{
    public int AssetId { get; set; }
    public ImpactType ImpactType { get; set; }
    public string? Notes { get; set; }
}
