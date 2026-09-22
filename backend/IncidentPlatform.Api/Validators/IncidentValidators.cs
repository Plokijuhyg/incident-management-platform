using FluentValidation;
using IncidentPlatform.Api.DTOs.Incidents;

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
        RuleFor(x => x.Status).IsInEnum();
    }
}

public class CloseIncidentRequestValidator : AbstractValidator<CloseIncidentRequest>
{
    public CloseIncidentRequestValidator()
    {
        RuleFor(x => x.ResolutionSummary).NotEmpty();
    }
}
