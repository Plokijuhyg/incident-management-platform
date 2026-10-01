namespace IncidentPlatform.Api.Services;
public sealed record ControlMapping(string Framework,string Control,string Status,string Rationale,string Reference);
public sealed record DetectionDefinition(string Id,string Name,string Channel,string Provider,int EventId,bool CanAutoPromote,string FalsePositives,string Reference,ControlMapping[] Mappings);
public static class DetectionCatalog
{
    public const string Revision = "2026-09-26.1";
    public static readonly ControlMapping[] Mappings = [
        new("NIST CSF 2.0","DE.AE-08","Partial","Local incident criteria and recorded decisions support this outcome; organizational criteria and review remain required.","https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20"),
        new("CIS Controls v8.1","8.2 / 8.9 / 8.11","Partial","Collection, centralized storage and review evidence for this host only; not enterprise-wide coverage.","https://cas.docs.cisecurity.org/en/latest/source/Controls8/"),
        new("ISO/IEC 27001:2022","Risk-based monitoring and incident management","Needs assessment","Technical evidence supports the ISMS. Scope, risk assessment, Statement of Applicability and licensed Annex A review remain required; no certification claim.","https://www.iso.org/standard/27001")
    ];
    public static readonly DetectionDefinition[] Rules = [
        new("WIN-DEFENDER-DETECTION","Defender threat detection","Microsoft-Windows-Windows Defender/Operational","Microsoft-Windows-Windows Defender",1116,true,"Potentially unwanted software, authorized lab samples or a detection already remediated. Detection is not proof of execution.","https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus",Mappings),
        new("WIN-AUDIT-CLEARED","Security audit log cleared","Security","Microsoft-Windows-Eventlog",1102,true,"Authorized maintenance or laboratory exercise. Confirm the clearing account and authorization.","https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102",Mappings),
        new("WIN-ACCOUNT-CREATED","Windows account created","Security","Microsoft-Windows-Security-Auditing",4720,false,"Normal account provisioning. Requires context and human review.","https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720",Mappings),
        new("WIN-LOCAL-GROUP-MEMBER","Local group membership changed","Security","Microsoft-Windows-Security-Auditing",4732,false,"Authorized group changes; the group may not be privileged. Requires human review.","https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732",Mappings)
    ];
    public static DetectionDefinition? Find(string id)=>Rules.SingleOrDefault(x=>x.Id==id);
}
