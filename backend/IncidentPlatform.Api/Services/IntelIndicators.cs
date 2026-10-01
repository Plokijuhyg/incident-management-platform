using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
namespace IncidentPlatform.Api.Services;
public static class IntelIndicators
{
    public static IEnumerable<IntelIndicator> FromPayload(string? payload)
    {
        if(string.IsNullOrEmpty(payload) || payload.Length>2*1024*1024)return [];
        var found=new List<IntelIndicator>();
        void Add(string name,string value)
        {
            var type=name.ToLowerInvariant() switch {"ip" or "ipaddress" or "ip_address" or "sourceip" or "destinationip" or "source_ip" or "destination_ip" or "src_ip" or "dst_ip"=>"ip", "domain" or "domainname" or "queryname"=>"domain", "url" or "uri"=>"url", "hash" or "md5" or "sha1" or "sha256"=>"hash", _=>""};
            if(VirusTotalClient.Normalize(type,value) is {} indicator && found.Count<100)found.Add(indicator);
        }
        void Walk(JsonElement node,int depth)
        {
            if(depth>12 || found.Count>=100)return;
            if(node.ValueKind==JsonValueKind.Object)foreach(var property in node.EnumerateObject())
            {
                if(property.Value.ValueKind==JsonValueKind.String)
                {
                    var value=property.Value.GetString()!;Add(property.Name,value);
                    if(property.Name.Equals("RawXml",StringComparison.OrdinalIgnoreCase))
                    {
                        try{using var reader=XmlReader.Create(new StringReader(value),new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null,MaxCharactersInDocument=1024*1024});
                        foreach(var element in XDocument.Load(reader).Descendants().Where(x=>!x.HasElements))Add(element.Attribute("Name")?.Value??element.Name.LocalName,element.Value);}
                        catch(XmlException){}
                    }
                }
                else Walk(property.Value,depth+1);
            }
            else if(node.ValueKind==JsonValueKind.Array)foreach(var item in node.EnumerateArray())Walk(item,depth+1);
        }
        try{using var doc=JsonDocument.Parse(payload);Walk(doc.RootElement,0);}catch(JsonException){}
        return found.Distinct().Take(50).ToArray();
    }
}
