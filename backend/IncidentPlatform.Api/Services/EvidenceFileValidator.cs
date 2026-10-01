namespace IncidentPlatform.Api.Services;

/// <summary>
/// Evidence upload is security-sensitive (database-design.md §4.8): only
/// an explicit allow-list of extensions/content-types is accepted. This is
/// deliberately conservative — a security-incident-management tool is an
/// especially unattractive place to allow arbitrary file uploads.
/// </summary>
public static class EvidenceFileValidator
{
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".png", ".jpg", ".jpeg", ".gif",
        ".txt", ".log", ".csv", ".json", ".xml",
        ".pdf", ".docx", ".xlsx",
        ".pcap", ".pcapng",
        ".zip" // for malware samples, per database-design.md §4.8 EvidenceType.MalwareSample — expected to be pre-encrypted/zipped by the analyst before upload, not executed
    };

    private static readonly HashSet<string> AllowedContentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "image/png", "image/jpeg", "image/gif",
        "text/plain", "text/csv", "application/json", "application/xml", "text/xml",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.tcpdump.pcap", "application/octet-stream", // pcap files commonly report as octet-stream
        "application/zip", "application/x-zip-compressed"
    };

    public static bool IsExtensionAllowed(string fileName) =>
        AllowedExtensions.Contains(Path.GetExtension(fileName));

    public static bool IsContentTypeAllowed(string contentType) =>
        AllowedContentTypes.Contains(contentType);

    /// <summary>
    /// Never trust the caller's original filename for storage path
    /// purposes — even after extension validation, strips anything that
    /// isn't a safe display character, purely for defense in depth.
    /// </summary>
    public static string SanitizeDisplayName(string fileName)
    {
        var name = Path.GetFileName(fileName); // strips any directory traversal component
        var invalidChars = Path.GetInvalidFileNameChars();
        return new string(name.Where(c => !invalidChars.Contains(c)).ToArray());
    }
}
