namespace IncidentPlatform.Api.Models;

/// <summary>
/// Stores only a SHA-256 hash of the refresh token, never the raw value —
/// same principle as password hashing: a leaked database row must not be
/// directly usable to impersonate a session.
///
/// Rotation model: every use of a valid token immediately revokes it and
/// issues a new one, linked via ReplacedByTokenHash. If a revoked token is
/// ever presented again, that's a signal of token theft (the legitimate
/// client already moved on to a newer token) — not a normal expiry case.
/// </summary>
public class RefreshToken
{
    public int Id { get; set; }

    public int UserId { get; set; }
    public User User { get; set; } = null!;

    public string TokenHash { get; set; } = string.Empty;

    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public string CreatedByIp { get; set; } = string.Empty;

    public DateTime? RevokedAt { get; set; }
    public string? RevokedByIp { get; set; }
    public string? ReplacedByTokenHash { get; set; }
    public string? ReasonRevoked { get; set; }

    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    public bool IsRevoked => RevokedAt is not null;
    public bool IsActive => !IsRevoked && !IsExpired;
}
