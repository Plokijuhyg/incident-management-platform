using IncidentPlatform.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace IncidentPlatform.Api.Data;

public static class MitreSeedData
{
    public record SeedTechnique(string TechniqueId, string Name, string Tactic, bool IsSubTechnique = false);

    public static readonly SeedTechnique[] Techniques =
    [
        new("T1566", "Phishing", "Initial Access"),
        new("T1566.001", "Spearphishing Attachment", "Initial Access", true),
        new("T1566.002", "Spearphishing Link", "Initial Access", true),
        new("T1190", "Exploit Public-Facing Application", "Initial Access"),
        new("T1078", "Valid Accounts", "Initial Access"),
        new("T1133", "External Remote Services", "Initial Access"),

        new("T1059", "Command and Scripting Interpreter", "Execution"),
        new("T1059.001", "PowerShell", "Execution", true),
        new("T1059.003", "Windows Command Shell", "Execution", true),
        new("T1053", "Scheduled Task/Job", "Execution"),
        new("T1204", "User Execution", "Execution"),

        new("T1547", "Boot or Logon Autostart Execution", "Persistence"),
        new("T1136", "Create Account", "Persistence"),
        new("T1098", "Account Manipulation", "Persistence"),

        new("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
        new("T1055", "Process Injection", "Privilege Escalation"),

        new("T1027", "Obfuscated Files or Information", "Defense Evasion"),
        new("T1070", "Indicator Removal", "Defense Evasion"),
        new("T1112", "Modify Registry", "Defense Evasion"),
        new("T1562", "Impair Defenses", "Defense Evasion"),

        new("T1110", "Brute Force", "Credential Access"),
        new("T1003", "OS Credential Dumping", "Credential Access"),
        new("T1555", "Credentials from Password Stores", "Credential Access"),

        new("T1082", "System Information Discovery", "Discovery"),
        new("T1083", "File and Directory Discovery", "Discovery"),
        new("T1018", "Remote System Discovery", "Discovery"),
        new("T1087", "Account Discovery", "Discovery"),

        new("T1021", "Remote Services", "Lateral Movement"),
        new("T1021.001", "Remote Desktop Protocol", "Lateral Movement", true),
        new("T1570", "Lateral Tool Transfer", "Lateral Movement"),

        new("T1005", "Data from Local System", "Collection"),
        new("T1114", "Email Collection", "Collection"),
        new("T1113", "Screen Capture", "Collection"),

        new("T1071", "Application Layer Protocol", "Command and Control"),
        new("T1105", "Ingress Tool Transfer", "Command and Control"),
        new("T1090", "Proxy", "Command and Control"),

        new("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        new("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),

        new("T1486", "Data Encrypted for Impact", "Impact"),
        new("T1490", "Inhibit System Recovery", "Impact"),
        new("T1489", "Service Stop", "Impact")
    ];

    public static async Task SeedAsync(AppDbContext context, CancellationToken cancellationToken = default)
    {
        // Pass 1: create every technique with no parent link yet, so
        // sub-techniques can find their parent's generated Id in pass 2
        // regardless of array order.
        var byTechniqueId = new Dictionary<string, MitreTechnique>();

        foreach (var seed in Techniques)
        {
            var existing = await context.MitreTechniques
                .FirstOrDefaultAsync(t => t.TechniqueId == seed.TechniqueId, cancellationToken);

            if (existing is not null)
            {
                byTechniqueId[seed.TechniqueId] = existing;
                continue;
            }

            var entity = new MitreTechnique
            {
                TechniqueId = seed.TechniqueId,
                Name = seed.Name,
                Tactic = seed.Tactic,
                IsSubTechnique = seed.IsSubTechnique,
                IsDeprecated = false,
                Url = $"https://attack.mitre.org/techniques/{seed.TechniqueId.Replace(".", "/")}/"
            };

            context.MitreTechniques.Add(entity);
            byTechniqueId[seed.TechniqueId] = entity;
        }

        await context.SaveChangesAsync(cancellationToken); // generates Ids

        // Pass 2: wire up ParentTechniqueId for sub-techniques (e.g.
        // T1566.001 -> T1566), matching on the base id before the dot.
        foreach (var seed in Techniques.Where(s => s.IsSubTechnique))
        {
            var parentTechniqueId = seed.TechniqueId.Split('.')[0];

            if (byTechniqueId.TryGetValue(parentTechniqueId, out var parent) &&
                byTechniqueId.TryGetValue(seed.TechniqueId, out var child) &&
                child.ParentTechniqueId is null)
            {
                child.ParentTechniqueId = parent.Id;
            }
        }

        await context.SaveChangesAsync(cancellationToken);
    }
}
