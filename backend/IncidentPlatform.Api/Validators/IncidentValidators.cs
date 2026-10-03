using FluentValidation;
using IncidentPlatform.Api.DTOs.Incidents;
using IncidentPlatform.Api.Models;

namespace IncidentPlatform.Api.Validators;

public class EscalateIncidentRequestValidator : AbstractValidator<EscalateIncidentRequest>
{
    public EscalateIncidentRequestValidator()
    {
        RuleFor(x => x.Tier).InclusiveBetween(1, 3);
        RuleFor(x => x.Note).MaximumLength(2000);
    }
}

public class IncidentQueryValidator : AbstractValidator<IncidentQuery>
{
    public IncidentQueryValidator()
    {
        RuleFor(x => x.Search).MaximumLength(200);
        RuleFor(x => x.Tier).InclusiveBetween(1, 3).When(x => x.Tier is not null);
        RuleFor(x => x.Sort).Must(s => s is null || IncidentQuery.SortKeys.Contains(s))
            .WithMessage($"Sort must be one of: {string.Join(", ", IncidentQuery.SortKeys)}.");
        RuleFor(x => x.Direction).Must(d => d is null or "asc" or "desc").WithMessage("Direction must be asc or desc.");
        RuleFor(x => x.Unassigned).Equal(false).When(x => x.AssignedToId is not null)
            .WithMessage("Use either assignedToId or unassigned, not both.");
        RuleFor(x => x.CreatedTo).GreaterThanOrEqualTo(x => x.CreatedFrom)
            .When(x => x.CreatedFrom is not null && x.CreatedTo is not null)
            .WithMessage("CreatedTo cannot be earlier than CreatedFrom.");
    }
}

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
