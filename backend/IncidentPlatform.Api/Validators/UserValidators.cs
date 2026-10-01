using FluentValidation;
using IncidentPlatform.Api.DTOs.Users;

namespace IncidentPlatform.Api.Validators;

public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
{
    public CreateUserRequestValidator()
    {
        RuleFor(x => x.Email).NotEmpty().EmailAddress().MaximumLength(256);
        RuleFor(x => x.FullName).NotEmpty().MaximumLength(150);
        RuleFor(x => x.JobTitle).MaximumLength(100);

        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(8).WithMessage("Password must be at least 8 characters.")
            .Matches("[A-Z]").WithMessage("Password must contain an uppercase letter.")
            .Matches("[a-z]").WithMessage("Password must contain a lowercase letter.")
            .Matches("[0-9]").WithMessage("Password must contain a digit.");

        RuleFor(x => x.Roles).NotEmpty().WithMessage("At least one role must be assigned.");
    }
}

public class UpdateUserRequestValidator : AbstractValidator<UpdateUserRequest>
{
    public UpdateUserRequestValidator()
    {
        RuleFor(x => x.FullName).NotEmpty().MaximumLength(150);
        RuleFor(x => x.JobTitle).MaximumLength(100);
    }
}

public class ReplaceRolesRequestValidator : AbstractValidator<ReplaceRolesRequest>
{
    public ReplaceRolesRequestValidator()
    {
        RuleFor(x => x.Roles).NotEmpty().WithMessage("At least one role must be assigned.");
    }
}
