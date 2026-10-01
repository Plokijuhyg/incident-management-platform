using FluentValidation;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Validators;

public class IncidentCreateRequestValidator : AbstractValidator<IncidentCreateRequest>
{
    public IncidentCreateRequestValidator()
    {
        RuleFor(x => x.Title).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Description).NotEmpty();
        RuleFor(x => x.Severity).IsInEnum();
        RuleFor(x => x.Priority).IsInEnum();
        RuleFor(x => x.Category).IsInEnum();
        RuleFor(x => x.Source).IsInEnum();
        RuleFor(x => x.OccurredAt).Must((request, occurred) => occurred is null ||
            (request.DetectedAt is not null && occurred <= request.DetectedAt))
            .WithMessage("OccurredAt requires DetectedAt and cannot be later than detection.");
    }
}

public class IncidentUpdateRequestValidator : AbstractValidator<IncidentUpdateRequest>
{
    public IncidentUpdateRequestValidator()
    {
        RuleFor(x => x.Title).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Description).NotEmpty();
        RuleFor(x => x.Severity).IsInEnum();
        RuleFor(x => x.Priority).IsInEnum();
        RuleFor(x => x.Category).IsInEnum();
    }
}

public class AssignIncidentRequestValidator : AbstractValidator<AssignIncidentRequest>
{
    public AssignIncidentRequestValidator()
    {
        RuleFor(x => x.AssignedToId).GreaterThan(0);
    }
}

public class ChangeStatusRequestValidator : AbstractValidator<ChangeStatusRequest>
{
    public ChangeStatusRequestValidator()
    {
        RuleFor(x => x.Status).IsInEnum()
            .NotEqual(IncidentStatus.Closed)
            .WithMessage("Use the close endpoint to close an incident; it requires a resolution summary.");
    }
}

public class CloseIncidentRequestValidator : AbstractValidator<CloseIncidentRequest>
{
    public CloseIncidentRequestValidator()
    {
        RuleFor(x => x.ResolutionSummary).NotEmpty();
    }
}
