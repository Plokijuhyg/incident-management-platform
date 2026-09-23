using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.DTOs.IncidentSubResources;

public class CommentResponse
{
    public int Id { get; set; }
    public string AuthorName { get; set; } = string.Empty;
    public int AuthorId { get; set; }
    public string Body { get; set; } = string.Empty;
    public bool IsInternal { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? EditedAt { get; set; }
}

public class CreateCommentRequest
{
    public string Body { get; set; } = string.Empty;
    public bool IsInternal { get; set; }
}

public class TimelineEventResponse
{
    public int Id { get; set; }
    public TimelineEventType EventType { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public DateTime OccurredAt { get; set; }
    public DateTime RecordedAt { get; set; }
    public string? ActorName { get; set; }
    public bool IsSystemGenerated { get; set; }
}

public class CreateTimelineEventRequest
{
    public TimelineEventType EventType { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public DateTime OccurredAt { get; set; }
}

public class ResponseActionResponse
{
    public int Id { get; set; }
    public ResponseActionType ActionType { get; set; }
    public string Description { get; set; } = string.Empty;
    public ResponseTargetType? TargetType { get; set; }
    public string? TargetValue { get; set; }
    public int? TargetAssetId { get; set; }
    public ResponseActionStatus Status { get; set; }
    public string? Result { get; set; }
    public string PerformedByName { get; set; } = string.Empty;
    public DateTime? PlannedAt { get; set; }
    public DateTime? PerformedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
}

public class CreateResponseActionRequest
{
    public ResponseActionType ActionType { get; set; }
    public string Description { get; set; } = string.Empty;
    public ResponseTargetType? TargetType { get; set; }
    public string? TargetValue { get; set; }
    public int? TargetAssetId { get; set; }
}

public class UpdateResponseActionRequest
{
    public ResponseActionStatus Status { get; set; }
    public string? Result { get; set; }
}
