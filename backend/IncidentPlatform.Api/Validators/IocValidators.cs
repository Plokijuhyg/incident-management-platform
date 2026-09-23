using FluentValidation;
using IncidentPlatform.Api.DTOs.Iocs;

namespace IncidentPlatform.Api.Validators;

public class IocCreateRequestValidator : AbstractValidator<IocCreateRequest>
{
    public IocCreateRequestValidator()
    {
        RuleFor(x => x.Type).IsInEnum();
        RuleFor(x => x.Value).NotEmpty().MaximumLength(512);
        RuleFor(x => x.Confidence).IsInEnum();
    }
}

public class IocUpdateRequestValidator : AbstractValidator<IocUpdateRequest>
{
    public IocUpdateRequestValidator()
    {
        RuleFor(x => x.Confidence).IsInEnum();
    }
}

public class LinkIocToIncidentRequestValidator : AbstractValidator<LinkIocToIncidentRequest>
{
    public LinkIocToIncidentRequestValidator()
    {
        RuleFor(x => x.Type).IsInEnum();
        RuleFor(x => x.Value).NotEmpty().MaximumLength(512);
        RuleFor(x => x.Confidence).IsInEnum();
        RuleFor(x => x.Role).IsInEnum();
    }
}
