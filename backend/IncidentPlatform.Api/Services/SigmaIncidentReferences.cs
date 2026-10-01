using System.Text.Json;
using System.Text.RegularExpressions;
using IncidentPlatform.Api.Data;
using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;
namespace IncidentPlatform.Api.Services;

public static class SigmaIncidentReferences
{
    public static async Task CopyAsync(AppDbContext db,Alert alert,int incidentId,int actorId,CancellationToken ct)
    {
        if(alert.Source!=AlertSource.WindowsEvent || alert.SourceRuleId?.StartsWith("SIGMA-",StringComparison.Ordinal)!=true || alert.RawPayload is null)return;
        using var payload=JsonDocument.Parse(alert.RawPayload);
        var p=payload.RootElement;
        if(p.ValueKind!=JsonValueKind.Object || !p.TryGetProperty("eventFingerprint",out var fp) || fp.ValueKind!=JsonValueKind.String || !p.TryGetProperty("tags",out var tags) || tags.ValueKind!=JsonValueKind.Array)return;
        var fingerprint=fp.GetString();
        if(alert.DeduplicationKey!="sigma:"+alert.SourceRuleId[6..]+":"+fingerprint ||
            !await db.WindowsEvents.AnyAsync(e=>e.Fingerprint==fingerprint,ct))return;
        var ids=tags.EnumerateArray().Where(t=>t.ValueKind==JsonValueKind.String).Select(t=>t.GetString()!)
            .Where(t=>Regex.IsMatch(t,@"\Aattack\.t[0-9]{4}(\.[0-9]{3})?\z",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant))
            .Select(t=>t[7..].ToUpperInvariant()).Distinct().ToArray();
        var techniques=await db.MitreTechniques.Where(t=>ids.Contains(t.TechniqueId)).Select(t=>t.Id).ToListAsync(ct);
        foreach(var technique in techniques)
            db.IncidentMitreTechniques.Add(new(){IncidentId=incidentId,MitreTechniqueId=technique,AddedById=actorId,AddedAt=DateTime.UtcNow,
                Notes="Published Sigma rule reference from "+alert.SourceRuleId+". Documentation mapping only; technique attribution has not been independently confirmed."});
    }
}
