namespace IncidentPlatform.Api.Models;

public sealed class WindowsEvent
{
    public long Id { get; set; }
    public string Fingerprint { get; set; } = "";
    public string Machine { get; set; } = "";
    public string Channel { get; set; } = "";
    public string Provider { get; set; } = "";
    public long? RecordId { get; set; }
    public int EventId { get; set; }
    public int Level { get; set; }
    public DateTime? TimeCreated { get; set; }
    public DateTime ReceivedAt { get; set; }
    public string Message { get; set; } = "";
    public string RawXml { get; set; } = "";
    public int? AlertId { get; set; }
}
public sealed class WindowsEventCheckpoint
{
    public int Id { get; set; }
    public string Machine { get; set; } = "";
    public string Channel { get; set; } = "";
    public bool Enabled { get; set; }
    public string? Bookmark { get; set; }
    public DateTime StartedAt { get; set; }
    public DateTime? LastCheckedAt { get; set; }
    public DateTime? LastEventAt { get; set; }
    public string? Error { get; set; }
    public bool HasBacklog { get; set; }
}
