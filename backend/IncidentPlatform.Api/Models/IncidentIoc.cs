namespace IncidentPlatform.Api.Models;

public enum IocRole
{
    Source,
    Payload,
    C2,
    Dropper,
    ExfilTarget,
    Affected,
    Other
}

/// <summary>
/// The "sighting" side of the IOC catalog design (database-design.md §3.1
/// / §4.5). Role/Notes describe this IOC's part in *this* incident — "this
/// hash was the dropper" is a fact about a sighting, not the hash itself.
/// </summary>
public class IncidentIoc
{
    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    public int IocId { get; set; }
    public Ioc Ioc { get; set; } = null!;

    public IocRole Role { get; set; }
    public string? Notes { get; set; }

    public int AddedById { get; set; }
    public User AddedBy { get; set; } = null!;

    public DateTime AddedAt { get; set; }
}
