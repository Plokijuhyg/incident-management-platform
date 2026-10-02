using FluentValidation;
using IncidentPlatform.Api.DTOs.Logs;

namespace IncidentPlatform.Api.Validators;

public sealed class IngestRequestValidator : AbstractValidator<IngestRequest>
{
    public IngestRequestValidator()
    {
        RuleFor(x => x.Source).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Format).IsInEnum();
        RuleFor(x => x.Lines).NotEmpty().WithMessage("Provide at least one log line.");
        RuleFor(x => x.Lines.Count).LessThanOrEqualTo(1000)
            .WithMessage("A batch is limited to 1000 lines.");
    }
}

public sealed class LogQueryValidator : AbstractValidator<LogQuery>
{
    public LogQueryValidator()
    {
        RuleFor(x => x.Search).MaximumLength(200);
        RuleFor(x => x.Source).MaximumLength(100);
        RuleFor(x => x.User).MaximumLength(255);
        RuleFor(x => x.Ip).MaximumLength(45);
        RuleFor(x => x.MaxSeverity).InclusiveBetween(0, 7).When(x => x.MaxSeverity is not null);
        RuleFor(x => x.Sort).Must(s => s is null || LogQuery.SortKeys.Contains(s))
            .WithMessage($"Sort must be one of: {string.Join(", ", LogQuery.SortKeys)}.");
        RuleFor(x => x.Direction).Must(d => d is null or "asc" or "desc").WithMessage("Direction must be asc or desc.");
        RuleFor(x => x.To).GreaterThanOrEqualTo(x => x.From)
            .When(x => x.From is not null && x.To is not null)
            .WithMessage("To cannot be earlier than From.");
    }
}
