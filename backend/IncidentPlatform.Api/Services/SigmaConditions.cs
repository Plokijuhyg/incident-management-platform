using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using IncidentPlatform.Api.Models;
namespace IncidentPlatform.Api.Services;

// Evaluates the typed tree produced by official pySigma inside the existing Windows detection path.
// No raw YAML, SQL, shell commands, or client-supplied severity is executed here.
public static class SigmaConditions
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);
    public static string? Unsupported(DetectionRule rule)
    {
        try
        {
            using var doc=JsonDocument.Parse(rule.DefinitionJson);
            var d=doc.RootElement;
            if(d.GetProperty("compilerVersion").GetInt32()!=1 || d.GetProperty("status").GetString()!="Compiled")
                return d.TryGetProperty("reason",out var reason)?reason.GetString()??"Definition not compiled":"Definition not compiled";
            if(!SourceSupported(d.GetProperty("logsource"))) return "No Windows event mapping for this log source.";
            Validate(d.GetProperty("compiled"),0);
            return null;
        }
        catch(Exception e) when(e is JsonException or InvalidOperationException or KeyNotFoundException or ArgumentException or NotSupportedException)
        { return "Unsupported definition: "+e.Message; }
    }
    private static string Text(JsonElement e,string name)=>e.TryGetProperty(name,out var v)?v.GetString()??"":"";
    private static bool SourceSupported(JsonElement s)=>Text(s,"product")=="windows" &&
        (Text(s,"service") is "security" or "system" or "application" or "windefend" or "powershell" or "powershell-classic" or "sysmon" ||
         Text(s,"category") is "process_creation" or "process_termination" or "network_connection" or "image_load" or "file_event" or "registry_event" or "registry_set" or "dns_query" or "ps_script" or "ps_module" or "process_access" or "create_remote_thread" or "driver_load" or "pipe_created" or "wmi_event");
    public static bool SourceMatches(JsonElement s,WindowsEvent e)
    {
        if(!SourceSupported(s))return false;
        var service=Text(s,"service"); var category=Text(s,"category");
        var serviceMatch=service switch {
            "security"=>e.Channel=="Security", "system"=>e.Channel=="System", "application"=>e.Channel=="Application",
            "windefend"=>e.Channel=="Microsoft-Windows-Windows Defender/Operational",
            "powershell"=>e.Channel=="Microsoft-Windows-PowerShell/Operational",
            "powershell-classic"=>e.Channel=="Windows PowerShell",
            "sysmon"=>e.Channel=="Microsoft-Windows-Sysmon/Operational", ""=>true, _=>false };
        if(!serviceMatch)return false;
        if(category=="")return true;
        if(category=="ps_script")return e.Channel=="Microsoft-Windows-PowerShell/Operational" && e.EventId==4104;
        if(category=="ps_module")return e.Channel=="Microsoft-Windows-PowerShell/Operational" && e.EventId==4103;
        // Generic process fields use Sysmon's taxonomy. Do not equate Security 4688 with Sysmon without a field pipeline.
        if(e.Channel!="Microsoft-Windows-Sysmon/Operational" || e.Provider!="Microsoft-Windows-Sysmon")return false;
        return category switch {
            "process_creation"=>e.EventId==1,"process_termination"=>e.EventId==5,"network_connection"=>e.EventId==3,
            "image_load"=>e.EventId==7,"file_event"=>e.EventId==11,"registry_event"=>e.EventId is 12 or 13 or 14,
            "registry_set"=>e.EventId==13,"registry_add" or "registry_delete"=>e.EventId==12,
            "dns_query"=>e.EventId==22,"process_access"=>e.EventId==10,"create_remote_thread"=>e.EventId==8,
            "driver_load"=>e.EventId==6,"pipe_created"=>e.EventId is 17 or 18,"wmi_event"=>e.EventId is 19 or 20 or 21,_=>false};
    }
    public static Dictionary<string,string[]> Fields(WindowsEvent e)
    {
        var fields=new Dictionary<string,string[]>(StringComparer.OrdinalIgnoreCase);
        using var reader=XmlReader.Create(new StringReader(e.RawXml),new XmlReaderSettings { DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=1024*1024 });
        var xml=XDocument.Load(reader); XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        foreach(var group in xml.Descendants(ns+"EventData").Elements(ns+"Data").Where(x=>x.Attribute("Name")!=null).GroupBy(x=>x.Attribute("Name")!.Value,StringComparer.OrdinalIgnoreCase))
            fields[group.Key]=group.Select(x=>x.Value).ToArray();
        foreach(var group in xml.Descendants(ns+"UserData").Descendants().Where(x=>!x.HasElements).GroupBy(x=>x.Name.LocalName,StringComparer.OrdinalIgnoreCase))
            fields.TryAdd(group.Key,group.Select(x=>x.Value).ToArray());
        fields["EventID"]=[e.EventId.ToString(CultureInfo.InvariantCulture)];
        // Event 104 carries the cleared log in UserData/Channel; preserve that field.
        fields.TryAdd("Channel",[e.Channel]);fields["EventChannel"]=[e.Channel];
        fields["Provider_Name"]=[e.Provider];fields["Computer"]=[e.Machine];fields["Message"]=[e.Message];
        fields["Level"]=[e.Level.ToString(CultureInfo.InvariantCulture)];
        if(e.RecordId is long record)fields["EventRecordID"]=[record.ToString(CultureInfo.InvariantCulture)];
        if(e.TimeCreated is DateTime created)fields["TimeCreated"]=[created.ToString("O",CultureInfo.InvariantCulture)];
        var system=xml.Root?.Element(ns+"System");
        foreach(var name in new[]{"ProcessID","ThreadID"})
            if(system?.Element(ns+"Execution")?.Attribute(name) is XAttribute execution)fields.TryAdd(name,[execution.Value]);
        foreach(var name in new[]{"Task","Opcode","Keywords","Version"})
            if(system?.Element(ns+name) is XElement node)fields[name]=[node.Value];
        if(system?.Element(ns+"Security")?.Attribute("UserID") is XAttribute sid)fields["UserID"]=[sid.Value];
        return fields;
    }
    public static bool Matches(DetectionRule rule,WindowsEvent e,Dictionary<string,string[]> fields)
    {
        using var doc=JsonDocument.Parse(rule.DefinitionJson);var d=doc.RootElement;
        if(!SourceMatches(d.GetProperty("logsource"),e))return false;
        return Node(d.GetProperty("compiled"),fields,e.Message);
    }
    private static void Validate(JsonElement n,int depth)
    {
        if(depth>64)throw new NotSupportedException("Condition depth exceeds 64");
        switch(Text(n,"op")) {
            case "and":case "or":case "not":
                var args=n.GetProperty("args"); if(args.GetArrayLength()==0 || (Text(n,"op")=="not" && args.GetArrayLength()!=1))throw new NotSupportedException("Invalid boolean operands");
                foreach(var a in args.EnumerateArray())Validate(a,depth+1);break;
            case "field":ValidateValue(n.GetProperty("value"));break;
            case "keyword":throw new NotSupportedException("Unbound keyword search requires a reviewed raw-event field mapping");
            default:throw new NotSupportedException("Unknown condition operator");
        }
    }
    private static void ValidateValue(JsonElement v)
    {
        switch(Text(v,"kind")) {
            case "string":_ = new Regex(Pattern(v),RegexOptions.CultureInvariant,RegexTimeout);break;
            case "regex":_ = new Regex(Text(v,"pattern"),RegexFlags(v),RegexTimeout);break;
            case "number":case "bool":case "null":case "exists":case "field":break;
            case "compare":if(Text(v,"operator") is not ("LT" or "LTE" or "GT" or "GTE"))throw new NotSupportedException("Unknown numeric comparison");break;
            case "cidr":if(!IPNetwork.TryParse(Text(v,"value"),out _))throw new NotSupportedException("Invalid CIDR");break;
            case "expansion":foreach(var a in v.GetProperty("values").EnumerateArray())ValidateValue(a);break;
            default:throw new NotSupportedException("Unknown typed value");
        }
    }
    private static bool Node(JsonElement n,Dictionary<string,string[]> f,string message)=>Text(n,"op") switch {
        "and"=>n.GetProperty("args").EnumerateArray().All(x=>Node(x,f,message)),
        "or"=>n.GetProperty("args").EnumerateArray().Any(x=>Node(x,f,message)),
        "not"=>!Node(n.GetProperty("args")[0],f,message),
        "field"=>Value(n.GetProperty("value"),f.GetValueOrDefault(Text(n,"field")),f),
        "keyword"=>Value(n.GetProperty("value"),[message],f),
        _=>throw new NotSupportedException("Unknown condition")};
    private static RegexOptions RegexFlags(JsonElement v)
    {
        var flags=Text(v,"flags");return RegexOptions.CultureInvariant |
            (flags.Contains('i')?RegexOptions.IgnoreCase:0)|(flags.Contains('m')?RegexOptions.Multiline:0)|(flags.Contains('s')?RegexOptions.Singleline:0);
    }
    private static string Pattern(JsonElement v)=>"\\A"+string.Concat(v.GetProperty("parts").EnumerateArray().Select(x=>
        x.TryGetProperty("text",out var t)?Regex.Escape(t.GetString()!):Text(x,"wildcard")=="*"?"[\\s\\S]*":"[\\s\\S]"))+"\\z";
    private static bool Value(JsonElement v,string[]? values,Dictionary<string,string[]> f)
    {
        var kind=Text(v,"kind");
        if(kind=="null")return values is null;
        if(kind=="exists")return (values is not null)==v.GetProperty("value").GetBoolean();
        if(kind=="expansion")return v.GetProperty("values").EnumerateArray().Any(x=>Value(x,values,f));
        if(values is null)return false;
        return values.Any(s=>kind switch {
            "string"=>Regex.IsMatch(s,Pattern(v),RegexOptions.CultureInvariant|(v.GetProperty("cased").GetBoolean()?0:RegexOptions.IgnoreCase),RegexTimeout),
            "regex"=>Regex.IsMatch(s,Text(v,"pattern"),RegexFlags(v),RegexTimeout),
            "bool"=>bool.TryParse(s,out var b)&&b==v.GetProperty("value").GetBoolean(),
            "number"=>decimal.TryParse(s,NumberStyles.Float,CultureInfo.InvariantCulture,out var n)&&n==v.GetProperty("value").GetDecimal(),
            "compare"=>Compare(s,v),
            "cidr"=>IPAddress.TryParse(s,out var ip)&&IPNetwork.Parse(Text(v,"value")).Contains(ip),
            "field"=>f.TryGetValue(Text(v,"field"),out var other)&&other.Any(o=>
                v.GetProperty("startsWith").GetBoolean()?s.StartsWith(o,StringComparison.OrdinalIgnoreCase):
                v.GetProperty("endsWith").GetBoolean()?s.EndsWith(o,StringComparison.OrdinalIgnoreCase):s.Equals(o,StringComparison.OrdinalIgnoreCase)),
            _=>throw new NotSupportedException("Unsupported typed value")});
    }
    private static bool Compare(string s,JsonElement v)
    {
        if(!decimal.TryParse(s,NumberStyles.Float,CultureInfo.InvariantCulture,out var a))return false;
        var b=v.GetProperty("value").GetDecimal();return Text(v,"operator") switch {"LT"=>a<b,"LTE"=>a<=b,"GT"=>a>b,"GTE"=>a>=b,_=>throw new NotSupportedException("Unknown comparison")};
    }
}
