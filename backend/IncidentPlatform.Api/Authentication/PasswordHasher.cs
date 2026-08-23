using Microsoft.AspNetCore.Identity;

namespace IncidentPlatform.Api.Authentication;

/// <summary>
/// Wraps ASP.NET Core Identity's PasswordHasher&lt;TUser&gt; standalone —
/// used purely for its PBKDF2 hashing algorithm, without pulling in the
/// rest of the Identity framework (UserManager, Identity's own DbContext
/// tables, etc.), which would conflict with our custom User/Role schema
/// from Phase 4.
///
/// The generic type parameter TUser is required by Identity's API but
/// unused by the hashing logic itself — `object` is a valid, if slightly
/// odd-looking, substitute here.
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    private readonly Microsoft.AspNetCore.Identity.PasswordHasher<object> _identityHasher = new();

    public string Hash(string password)
    {
        // The `object` argument is Identity's "user" parameter — genuinely
        // unused by the PBKDF2 implementation itself, just part of the
        // generic API shape. Passing null! is safe here.
        return _identityHasher.HashPassword(null!, password);
    }

    public bool Verify(string hashedPassword, string providedPassword)
    {
        var result = _identityHasher.VerifyHashedPassword(null!, hashedPassword, providedPassword);

        // PasswordVerificationResult has three states: Failed, Success, and
        // SuccessRehashNeeded (the hash used an older/weaker algorithm
        // version and should be silently re-hashed on next successful
        // login). We treat both Success and SuccessRehashNeeded as valid
        // for now — implementing the rehash-on-login upgrade path is a
        // reasonable future enhancement, not required for the MVP.
        return result is PasswordVerificationResult.Success
            or PasswordVerificationResult.SuccessRehashNeeded;
    }
}
