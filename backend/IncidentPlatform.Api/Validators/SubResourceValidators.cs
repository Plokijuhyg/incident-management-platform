using FluentValidation;
using IncidentPlatform.Api.DTOs.IncidentSubResources;

namespace IncidentPlatform.Api.Validators;

public class CreateCommentRequestValidator : AbstractValidator<CreateCommentRequest>
{
    public CreateCommentRequestValidator()
    {
        RuleFor(x => x.Body).NotEmpty();
    }
}

public class CreateTimelineEventRequestValidator : AbstractValidator<CreateTimelineEventRequest>
{
    public CreateTimelineEventRequestValidator()
    {
        RuleFor(x => x.EventType).IsInEnum();
        RuleFor(x => x.Title).NotEmpty().MaximumLength(200);
    }
}

public class CreateResponseActionRequestValidator : AbstractValidator<CreateResponseActionRequest>
{
    public CreateResponseActionRequestValidator()
    {
        RuleFor(x => x.ActionType).IsInEnum();
        RuleFor(x => x.Description).NotEmpty();
    }
}

public class UpdateResponseActionRequestValidator : AbstractValidator<UpdateResponseActionRequest>
{
    public UpdateResponseActionRequestValidator()
    {
        RuleFor(x => x.Status).IsInEnum();
    }
}
