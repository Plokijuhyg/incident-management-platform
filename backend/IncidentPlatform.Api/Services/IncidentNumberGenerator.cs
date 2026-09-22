using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Services;

/// <summary>
/// Shared by IncidentService (direct create) and AlertService (promote) —
/// both need the same race-safe SELECT...FOR UPDATE numbering logic
/// (database-design.md §3.3), and must run inside the caller's own
/// transaction, not its own.
/// </summary>
public static class IncidentNumberGenerator
{
    public static async Task<string> GenerateNextAsync(AppDbContext db, CancellationToken cancellationToken)
    {
        var year = DateTime.UtcNow.Year;

        var sequence = await db.IncidentNumberSequences
            .FromSqlInterpolated($"SELECT * FROM IncidentNumberSequences WHERE Year = {year} FOR UPDATE")
            .SingleOrDefaultAsync(cancellationToken);

        if (sequence is null)
        {
            sequence = new IncidentNumberSequence { Year = year, LastValue = 0, UpdatedAt = DateTime.UtcNow };
            db.IncidentNumberSequences.Add(sequence);
        }

        sequence.LastValue++;
        sequence.UpdatedAt = DateTime.UtcNow;

        return $"INC-{year}-{sequence.LastValue:D6}";
    }
}