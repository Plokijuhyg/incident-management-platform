using System.ComponentModel.DataAnnotations;

namespace IncidentPlatform.Api.Configuration;

public sealed class JwtSettings
{
    public const string SectionName = "Jwt";

    [Required]
    [MinLength(32, ErrorMessage = "Jwt:Secret must be at least 32 characters for HS256 signing.")]
    public string Secret { get; init; } = string.Empty;

    [Required]
    public string Issuer { get; init; } = string.Empty;

    [Required]
    public string Audience { get; init; } = string.Empty;

    [Range(1, 1440, ErrorMessage = "Jwt:AccessTokenExpirationMinutes must be between 1 and 1440.")]
    public int AccessTokenExpirationMinutes { get; init; } = 15;

    [Range(1, 90, ErrorMessage = "Jwt:RefreshTokenExpirationDays must be between 1 and 90.")]
    public int RefreshTokenExpirationDays { get; init; } = 7;
}

