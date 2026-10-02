using FluentValidation;
using IncidentPlatform.Api.DTOs.Alerts;

namespace IncidentPlatform.Api.Validators;

public class AlertQueryValidator : AbstractValidator<AlertQuery>
{
    public AlertQueryValidator()
    {
        RuleFor(x => x.Search).MaximumLength(200);
        RuleFor(x => x.Severity).MaximumLength(20);
        RuleFor(x => x.Sort).Must(s => s is null || AlertQuery.SortKeys.Contains(s))
            .WithMessage($"Sort must be one of: {string.Join(", ", AlertQuery.SortKeys)}.");
        RuleFor(x => x.Direction).Must(d => d is null or "asc" or "desc").WithMessage("Direction must be asc or desc.");
        RuleFor(x => x.DetectedTo).GreaterThanOrEqualTo(x => x.DetectedFrom)
            .When(x => x.DetectedFrom is not null && x.DetectedTo is not null)
            .WithMessage("DetectedTo cannot be earlier than DetectedFrom.");
    }
}

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