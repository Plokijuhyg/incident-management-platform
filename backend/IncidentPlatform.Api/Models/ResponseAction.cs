namespace IncidentPlatform.Api.Models;

public enum ResponseActionType
{
    DisableUser,
    BlockIp,
    BlockDomain,
    BlockHash,
    IsolateEndpoint,
    ResetPassword,
    RemoveMalware,
    ReimageDevice,
    RevokeSessions,
    PatchSystem,
    RestoreBackup,
    Other
}

public enum ResponseTargetType
{
    Asset,
    User,
    Ioc,
    Other
}

public enum ResponseActionStatus
{
    Planned,
    InProgress,
    Completed,
    Failed,
    RolledBack
}

/// <summary>
/// RolledBack and Failed are first-class statuses (database-design.md
/// §4.11): containment actions fail (an endpoint is offline, a block breaks
/// production and is reverted), and a response record that can only say
/// "done" is a record that lies.
///
/// TargetType/TargetValue capture targets that aren't modelled assets (an
/// external IP, a cloud identity); TargetAssetId is set additionally when
/// the target happens to be a known asset in our own inventory.
/// </summary>
public class ResponseAction
{
    public int Id { get; set; }

    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    public ResponseActionType ActionType { get; set; }
    public string Description { get; set; } = string.Empty;

    public ResponseTargetType? TargetType { get; set; }
    public string? TargetValue { get; set; }

    public int? TargetAssetId { get; set; }
    public Asset? TargetAsset { get; set; }

    public ResponseActionStatus Status { get; set; }
    public string? Result { get; set; }

    public int PerformedById { get; set; }
    public User PerformedBy { get; set; } = null!;

    public DateTime? PlannedAt { get; set; }
    public DateTime? PerformedAt { get; set; }
    public DateTime? CompletedAt { get; set; }
}
