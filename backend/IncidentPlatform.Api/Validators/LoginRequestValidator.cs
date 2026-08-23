using FluentValidation;
using IncidentPlatform.Api.DTOs.Auth;

namespace IncidentPlatform.Api.Validators;

public class LoginRequestValidator : AbstractValidator<LoginRequest>
{
    public LoginRequestValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        RuleFor(x => x.Password)
            .NotEmpty();

        // Deliberately NO password complexity rules here (length, character
        // classes) — this is the *login* validator. Complexity requirements
        // belong on registration/change-password, where a weak password is
        // actually being created. Applying them here would reject a
        // legitimately-set (if weak) existing password before it even
        // reaches the database check.
    }
}
