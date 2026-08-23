namespace IncidentPlatform.Api.Models;

public enum TimelineEventType
{
    Detection,
    AlertReceived,
    StatusChange,
    Assignment,
    IocIdentified,
    ContainmentAction,
    EvidenceAdded,
    AnalystNote,
    Communication,
    Escalation,
    Resolution,
    Other
}

/// <summary>
/// Structured rows, one per event — never one big text field (a text blob
/// can't be sorted, filtered by type, or exported into a report).
///
/// OccurredAt vs RecordedAt is the important distinction here
/// (database-design.md §4.9): an analyst at 14:00 recording "malware
/// executed at 09:47 per the EDR log" is stating one fact with two
/// timestamps. Only OccurredAt belongs on the reconstructed attack
/// timeline; only RecordedAt reflects analyst activity. RecordedAt is
/// system-set and immutable; OccurredAt is analyst-supplied and can predate
/// the record — which is intentional, not a bug to "fix" with one column.
/// </summary>
public class IncidentTimelineEvent
{
    public int Id { get; set; }

    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    public TimelineEventType EventType { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }

    public DateTime OccurredAt { get; set; }
    public DateTime RecordedAt { get; set; }

    public int? ActorUserId { get; set; }
    public User? ActorUser { get; set; }

    public bool IsSystemGenerated { get; set; }
}
