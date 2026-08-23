namespace IncidentPlatform.Api.Models;

/// <summary>
/// Separate from timeline events on purpose (database-design.md §4.10):
/// comments are discussion, timeline events are the factual record. Mixing
/// them means "Bob, can you check this?" pollutes the forensic timeline.
/// </summary>
public class IncidentComment
{
    public int Id { get; set; }

    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    public int AuthorId { get; set; }
    public User Author { get; set; } = null!;

    public string Body { get; set; } = string.Empty;

    /// <summary>
    /// Excluded from exported customer-facing reports.
    /// </summary>
    public bool IsInternal { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? EditedAt { get; set; }
}
