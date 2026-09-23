using IncidentPlatform.Api.DTOs.IncidentSubResources;

namespace IncidentPlatform.Api.Interfaces;

public interface IIncidentSubResourceService
{
    Task<List<CommentResponse>> GetCommentsAsync(int incidentId, CancellationToken cancellationToken = default);
    Task<CommentResponse> AddCommentAsync(int incidentId, CreateCommentRequest request, CancellationToken cancellationToken = default);

    Task<List<TimelineEventResponse>> GetTimelineAsync(int incidentId, CancellationToken cancellationToken = default);
    Task<TimelineEventResponse> AddTimelineEventAsync(int incidentId, CreateTimelineEventRequest request, CancellationToken cancellationToken = default);

    Task<List<ResponseActionResponse>> GetResponseActionsAsync(int incidentId, CancellationToken cancellationToken = default);
    Task<ResponseActionResponse> AddResponseActionAsync(int incidentId, CreateResponseActionRequest request, CancellationToken cancellationToken = default);
    Task<ResponseActionResponse> UpdateResponseActionAsync(int incidentId, int actionId, UpdateResponseActionRequest request, CancellationToken cancellationToken = default);
}
