namespace IncidentPlatform.Api.Models;

public enum AssetType
{
    Workstation,
    Server,
    NetworkDevice,
    CloudResource,
    MobileDevice,
    Application,
    UserAccount,
    Other
}

public enum AssetCriticality
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Criticality is the asset's business importance and is a direct input to
/// incident *priority* (database-design.md §4.6) — this is the column that
/// makes the severity/priority distinction computable rather than a vibe.
/// </summary>
public class Asset
{
    public int Id { get; set; }
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
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
