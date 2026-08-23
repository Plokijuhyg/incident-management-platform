namespace IncidentPlatform.Api.Authentication;

/// <summary>
/// Abstraction over password hashing so services depend on this interface,
/// not directly on Microsoft.AspNetCore.Identity's PasswordHasher&lt;TUser&gt;
/// — keeps services testable and keeps the hashing implementation swappable
/// in one place if it's ever upgraded (e.g. to Argon2) later.
/// </summary>
public interface IPasswordHasher
{
    string Hash(string password);

    /// <summary>
    /// Returns true if the plaintext password matches the stored hash.
    /// Deliberately returns only a bool — never throws on a wrong password,
    /// and never lets a caller distinguish "wrong password" from "malformed
    /// hash" from the return type alone.
    /// </summary>
    bool Verify(string hashedPassword, string providedPassword);
}
