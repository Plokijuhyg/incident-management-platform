namespace IncidentPlatform.Api.Models;

public enum EvidenceType
{
    Screenshot,
    LogFile,
    Report,
    MemoryDump,
    Pcap,
    MalwareSample,
    Document,
    Other
}

public enum StorageProvider
{
    LocalFilesystem,
    S3,
    AzureBlob
}

/// <summary>
/// Metadata in MySQL, file bytes on disk — never a BLOB column (a 50 MB
/// memory dump in a row bloats backups and streams badly).
///
/// StoredFileName decoupled from OriginalFileName is a security control,
/// not tidiness (database-design.md §4.8): a random name defeats path
/// traversal, prevents collisions, and stops an uploaded .aspx from ever
/// sitting at a guessable, servable path. Files live outside the web root;
/// the actual upload/download/storage logic is Phase 5+ service code, not
/// this entity.
///
/// Sha256 is the chain-of-custody anchor — it proves the file wasn't
/// altered after collection.
/// </summary>
public class Evidence
{
    public int Id { get; set; }

    public int IncidentId { get; set; }
    public Incident Incident { get; set; } = null!;

    public string OriginalFileName { get; set; } = string.Empty;
    public string StoredFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public string Sha256 { get; set; } = string.Empty;
    public EvidenceType EvidenceType { get; set; }
    public string? Description { get; set; }
    public StorageProvider StorageProvider { get; set; }

    public int UploadedById { get; set; }
    public User UploadedBy { get; set; } = null!;

    public DateTime UploadedAt { get; set; }
}
