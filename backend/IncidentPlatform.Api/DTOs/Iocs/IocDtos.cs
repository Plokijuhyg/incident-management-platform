using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.DTOs.Iocs;

public class IocResponse
{
    public int Id { get; set; }
    public IocType Type { get; set; }
    public string Value { get; set; } = string.Empty;
    public string? RawValue { get; set; }
    public IocConfidence Confidence { get; set; }
    public bool? IsMalicious { get; set; }
    public string? Source { get; set; }
    public string? Description { get; set; }
    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public int SightingCount { get; set; }
}

public class IocDetailResponse : IocResponse
{
    public List<IocIncidentAppearance> Incidents { get; set; } = [];
}

public class IocIncidentAppearance
{
    public int IncidentId { get; set; }
    public string IncidentNumber { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public IocRole Role { get; set; }
    public DateTime AddedAt { get; set; }
}

public class IocCreateRequest
{
    public IocType Type { get; set; }
    public string Value { get; set; } = string.Empty;
    public IocConfidence Confidence { get; set; }
    public bool? IsMalicious { get; set; }
    public string? Source { get; set; }
    public string? Description { get; set; }
}

public class IocUpdateRequest
{
    public IocConfidence Confidence { get; set; }
    public bool? IsMalicious { get; set; }
    public string? Description { get; set; }
}

public class LinkIocToIncidentRequest
{
    public IocType Type { get; set; }
    public string Value { get; set; } = string.Empty;
    public IocConfidence Confidence { get; set; }
    public IocRole Role { get; set; }
    public string? Notes { get; set; }
}

public class LinkIocResult
{
    public IocResponse Ioc { get; set; } = null!;
    public bool WasNewlyCreated { get; set; }
}
