using FluentValidation;
using IncidentPlatform.Api.DTOs.Assets;

namespace IncidentPlatform.Api.Validators;

public class AssetCreateRequestValidator : AbstractValidator<AssetCreateRequest>
{
    public AssetCreateRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Type).IsInEnum();
        RuleFor(x => x.Criticality).IsInEnum();
    }
}

public class AssetUpdateRequestValidator : AbstractValidator<AssetUpdateRequest>
{
    public AssetUpdateRequestValidator()
    {
        RuleFor(x => x.Name).NotEmpty().MaximumLength(200);
        RuleFor(x => x.Criticality).IsInEnum();
    }
}

public class LinkAssetToIncidentRequestValidator : AbstractValidator<LinkAssetToIncidentRequest>
{
    public LinkAssetToIncidentRequestValidator()
    {
        RuleFor(x => x.AssetId).GreaterThan(0);
        RuleFor(x => x.ImpactType).IsInEnum();
    }
}
