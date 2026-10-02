using System.Text.Json;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Data;

public partial class AppDbContext
{
    // Explicit allow-list: free text, raw payloads, file paths, password hashes and
    // token material never enter the audit JSON, including future entity fields.
    private static readonly HashSet<string> AuditFields = new(StringComparer.Ordinal)
    {
        "Email", "FullName", "JobTitle", "IsActive", "LastLoginAt", "FailedLoginAttempts", "LockedOutUntil", "UserId", "RoleId", "AssignedById",
        "IncidentNumber", "Severity", "Priority", "Status", "Category", "Source",
        "AssignedToId", "CreatedById", "IncidentId", "IocId", "AssetId", "MitreTechniqueId",
        "Type", "Confidence", "IsMalicious", "SightingCount", "ImpactType", "Role",
        "CreatedAt", "UpdatedAt", "AssignedAt", "AddedAt", "UploadedAt", "ActorUserId",
        "DetectedAt", "OccurredAt", "TriagedAt", "ContainedAt", "ResolvedAt", "ClosedAt",
        "Version", "EvidenceType", "SizeBytes", "UploadedById"
    };

    public async Task RecordEvidenceDownloadAsync(int evidenceId, CancellationToken ct)
    {
        if (_audit?.IsActive != true) return;
        AuditLogs.Add(_audit.Create("EVIDENCE_DOWNLOADED", "Evidence", evidenceId.ToString()));
        await SaveChangesAsync(ct);
    }

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        if (_audit?.IsActive == true)
            throw new InvalidOperationException("Request writes must use SaveChangesAsync for transactional auditing.");
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        if (_audit?.IsActive != true)
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);

        ChangeTracker.DetectChanges();
        if (ChangeTracker.Entries<AuditLog>().Any(e => e.State is EntityState.Modified or EntityState.Deleted))
            throw new InvalidOperationException("Audit records are append-only.");

        var pending = ChangeTracker.Entries()
            // LogEvent is high-volume ingested telemetry; it is covered by a single
            // per-batch summary audit row, not one row per line (see LogIngestionService).
            .Where(e => e.Entity is not AuditLog and not RefreshToken and not IncidentNumberSequence and not LogEvent &&
                e.State is EntityState.Added or EntityState.Modified or EntityState.Deleted)
            .Select(e => new
            {
                Entry = e,
                State = e.State,
                Fields = e.Properties.Where(p => !p.Metadata.IsPrimaryKey() &&
                        (e.State != EntityState.Modified || p.IsModified))
                    .ToDictionary(p => p.Metadata.Name, p => new
                    {
                        before = e.State == EntityState.Added ? null : AuditFields.Contains(p.Metadata.Name) ? p.OriginalValue : "[REDACTED]",
                        after = e.State == EntityState.Deleted ? null : AuditFields.Contains(p.Metadata.Name) ? p.CurrentValue : "[REDACTED]"
                    })
            }).Where(p => p.Fields.Count > 0).ToList();

        if (pending.Count == 0)
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
        if (!acceptAllChangesOnSuccess)
            throw new InvalidOperationException("Audited writes require accepting changes on success.");

        // Both the business write and its generated-key audit record commit together.
        var relational = Database.IsRelational();
        await using var transaction = relational && Database.CurrentTransaction is null
            ? await Database.BeginTransactionAsync(cancellationToken) : null;
        var existing = relational && transaction is null ? Database.CurrentTransaction : null;
        var savepoint = "audit_" + Guid.NewGuid().ToString("N");
        if (existing is not null) await existing.CreateSavepointAsync(savepoint, cancellationToken);
        try
        {
            var count = await base.SaveChangesAsync(true, cancellationToken);
            foreach (var change in pending)
            {
                var type = change.Entry.Metadata.ClrType.Name;
                var key = string.Join(":", change.Entry.Metadata.FindPrimaryKey()!.Properties
                    .Select(p => change.Entry.Property(p.Name).CurrentValue));
                var verb = change.State switch
                {
                    EntityState.Added => "CREATED", EntityState.Deleted => "DELETED", _ => "UPDATED"
                };
                var action = type == nameof(Evidence) && change.State == EntityState.Added
                    ? "EVIDENCE_UPLOADED" : type.ToUpperInvariant() + "_" + verb;
                AuditLogs.Add(_audit.Create(action, type, key,
                    details: JsonSerializer.Serialize(change.Fields)));
            }
            await base.SaveChangesAsync(true, cancellationToken);
            if (transaction is not null) await transaction.CommitAsync(cancellationToken);
            if (existing is not null) await existing.ReleaseSavepointAsync(savepoint, cancellationToken);
            return count;
        }
        catch
        {
            if (transaction is not null) await transaction.RollbackAsync(CancellationToken.None);
            if (existing is not null) await existing.RollbackToSavepointAsync(savepoint, CancellationToken.None);
            throw;
        }
    }
}
