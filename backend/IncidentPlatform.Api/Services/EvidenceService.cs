using System.Security.Cryptography;
using IncidentPlatform.Api.Configuration;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.DTOs.Evidence;
using IncidentPlatform.Api.Exceptions;
using IncidentPlatform.Api.Interfaces;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IncidentPlatform.Api.Services;

public class EvidenceService : IEvidenceService
{
    private readonly AppDbContext _dbContext;
    private readonly ICurrentUser _currentUser;
    private readonly EvidenceStorageSettings _storageSettings;

    public EvidenceService(AppDbContext dbContext, ICurrentUser currentUser, IOptions<EvidenceStorageSettings> storageSettings)
    {
        _dbContext = dbContext;
        _currentUser = currentUser;
        _storageSettings = storageSettings.Value;
    }

    public async Task<List<EvidenceResponse>> GetForIncidentAsync(int incidentId, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        return await _dbContext.Evidence
            .Where(e => e.IncidentId == incidentId)
            .OrderByDescending(e => e.UploadedAt)
            .Include(e => e.UploadedBy)
            .Select(e => ToResponse(e))
            .ToListAsync(cancellationToken);
    }

    public async Task<EvidenceResponse> UploadAsync(
        int incidentId, Stream fileStream, string originalFileName, string contentType, long sizeBytes,
        EvidenceType evidenceType, string? description, CancellationToken cancellationToken = default)
    {
        await EnsureIncidentExistsAsync(incidentId, cancellationToken);

        // Size check first â€” cheapest rejection, before touching disk.
        var maxBytes = _storageSettings.MaxFileSizeMb * 1024L * 1024L;
        if (sizeBytes > maxBytes)
        {
            throw new ValidationAppException($"File exceeds the maximum allowed size of {_storageSettings.MaxFileSizeMb} MB.");
        }

        if (!EvidenceFileValidator.IsExtensionAllowed(originalFileName))
        {
            throw new ValidationAppException("This file extension is not permitted for evidence upload.");
        }

        if (!EvidenceFileValidator.IsContentTypeAllowed(contentType))
        {
            throw new ValidationAppException("This content type is not permitted for evidence upload.");
        }

        var sanitizedName = EvidenceFileValidator.SanitizeDisplayName(originalFileName);

        // Random storage name, decoupled from the original â€” defeats path
        // traversal, prevents collisions, and never places an uploaded file
        // at a guessable, servable path (database-design.md Â§4.8).
        var extension = Path.GetExtension(sanitizedName);
        var storedFileName = $"{Guid.NewGuid():N}{extension}";

        Directory.CreateDirectory(_storageSettings.RootPath); // outside the web root, per Â§4.8
        var fullPath = Path.Combine(_storageSettings.RootPath, storedFileName);

        string sha256Hex;
        await using (var fileOnDisk = File.Create(fullPath))
        using (var sha256 = SHA256.Create())
        {
            await fileStream.CopyToAsync(fileOnDisk, cancellationToken);
            fileOnDisk.Position = 0;
            var hashBytes = await sha256.ComputeHashAsync(fileOnDisk, cancellationToken);
            sha256Hex = Convert.ToHexString(hashBytes).ToLowerInvariant();
        }

        var evidence = new Api.Models.Evidence
        {
            IncidentId = incidentId,
            OriginalFileName = sanitizedName,
            StoredFileName = storedFileName,
            ContentType = contentType,
            SizeBytes = sizeBytes,
            Sha256 = sha256Hex,
            EvidenceType = evidenceType,
            Description = description,
            StorageProvider = StorageProvider.LocalFilesystem,
            UploadedById = _currentUser.Id,
            UploadedAt = DateTime.UtcNow
        };

        _dbContext.Evidence.Add(evidence);

        _dbContext.IncidentTimelineEvents.Add(new IncidentTimelineEvent
        {
            IncidentId = incidentId,
            EventType = TimelineEventType.EvidenceAdded,
            Title = $"Evidence uploaded: {sanitizedName}",
            OccurredAt = DateTime.UtcNow,
            RecordedAt = DateTime.UtcNow,
            ActorUserId = _currentUser.Id,
            IsSystemGenerated = false
        });

        try
        {
            await _dbContext.SaveChangesAsync(cancellationToken);
        }
        catch
        {
            File.Delete(fullPath);
            throw;
        }
        await _dbContext.Entry(evidence).Reference(e => e.UploadedBy).LoadAsync(cancellationToken);

        return ToResponse(evidence);
    }

    public async Task<(Stream Stream, string ContentType, string FileName)> DownloadAsync(int incidentId, int evidenceId, CancellationToken cancellationToken = default)
    {
        var evidence = await _dbContext.Evidence
            .SingleOrDefaultAsync(e => e.Id == evidenceId && e.IncidentId == incidentId, cancellationToken)
            ?? throw new NotFoundException("Evidence", evidenceId);

        var fullPath = Path.Combine(_storageSettings.RootPath, evidence.StoredFileName);

        if (!File.Exists(fullPath))
        {
            // Metadata exists but the file is gone â€” a genuine server-side
            // problem, distinct from "this evidence id doesn't exist".
            throw new NotFoundException($"Evidence file for id {evidenceId} is missing from storage.");
        }

        var stream = File.OpenRead(fullPath);
        try
        {
            await _dbContext.RecordEvidenceDownloadAsync(evidenceId, cancellationToken);
            return (stream, evidence.ContentType, evidence.OriginalFileName);
        }
        catch
        {
            await stream.DisposeAsync();
            throw;
        }
    }

    public async Task DeleteAsync(int incidentId, int evidenceId, CancellationToken cancellationToken = default)
    {
        var evidence = await _dbContext.Evidence
            .SingleOrDefaultAsync(e => e.Id == evidenceId && e.IncidentId == incidentId, cancellationToken)
            ?? throw new NotFoundException("Evidence", evidenceId);

        var fullPath = Path.Combine(_storageSettings.RootPath, evidence.StoredFileName);
        // Persist the custody record before removing bytes. An audit failure leaves
        // the evidence accessible; an orphan after an I/O failure is inaccessible.
        _dbContext.Evidence.Remove(evidence);
        await _dbContext.SaveChangesAsync(cancellationToken);
        if (File.Exists(fullPath)) File.Delete(fullPath);
    }

    private async Task EnsureIncidentExistsAsync(int incidentId, CancellationToken cancellationToken)
    {
        var exists = await _dbContext.Incidents.AnyAsync(i => i.Id == incidentId, cancellationToken);
        if (!exists) throw new NotFoundException("Incident", incidentId);
    }

    private static EvidenceResponse ToResponse(Api.Models.Evidence e) => new()
    {
        Id = e.Id,
        OriginalFileName = e.OriginalFileName,
        ContentType = e.ContentType,
        SizeBytes = e.SizeBytes,
        Sha256 = e.Sha256,
        EvidenceType = e.EvidenceType,
        Description = e.Description,
        UploadedByName = e.UploadedBy?.FullName ?? string.Empty,
        UploadedAt = e.UploadedAt
    };
}
