using FluentValidation;
using IncidentPlatform.Api.DTOs.Alerts;

namespace IncidentPlatform.Api.Validators;

public class AlertCreateRequestValidator : AbstractValidator<AlertCreateRequest>
{
    public AlertCreateRequestValidator()
    {
        RuleFor(x => x.Title).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Source).IsInEnum();
        RuleFor(x => x.Severity).NotEmpty().MaximumLength(20);
    }
}

public class PromoteAlertRequestValidator : AbstractValidator<PromoteAlertRequest>
{
    public PromoteAlertRequestValidator()
    {
        RuleFor(x => x.Title).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Severity).IsInEnum();
        RuleFor(x => x.Priority).IsInEnum();
        RuleFor(x => x.Category).IsInEnum();
    }
}

public class FalsePositiveRequestValidator : AbstractValidator<FalsePositiveRequest>
{
    public FalsePositiveRequestValidator()
    {
        RuleFor(x => x.Reason).NotEmpty();
    }
}