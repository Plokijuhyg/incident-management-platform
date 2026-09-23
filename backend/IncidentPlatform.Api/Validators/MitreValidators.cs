using FluentValidation;
using IncidentPlatform.Api.DTOs.Mitre;

namespace IncidentPlatform.Api.Validators;

public class LinkMitreTechniqueRequestValidator : AbstractValidator<LinkMitreTechniqueRequest>
{
    public LinkMitreTechniqueRequestValidator()
    {
        RuleFor(x => x.MitreTechniqueId).GreaterThan(0);
    }
}
