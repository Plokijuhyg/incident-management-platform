using IncidentPlatform.Api.Services;
using System.Text.Json;
using System.Xml;
namespace IncidentPlatform.Tests;
public class AssessmentParserTests
{
 [Fact]public void Parses_real_Nmap_shape_without_claiming_vulnerabilities(){var json=AssessmentWorker.Normalize("<?xml version=\"1.0\"?>\n<!DOCTYPE nmaprun>\n<nmaprun><host><ports><port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\"/></port></ports></host><runstats><finished exit=\"success\"/></runstats></nmaprun>");var row=JsonDocument.Parse(json).RootElement[0];Assert.Equal("80",row.GetProperty("port").GetString());Assert.Equal("Informational",row.GetProperty("severity").GetString());}
 [Fact]public void Rejects_external_entities(){Assert.Throws<XmlException>(()=>AssessmentWorker.Normalize("<!DOCTYPE nmaprun [<!ENTITY x SYSTEM 'file:///secret'>]><nmaprun>&x;</nmaprun>"));}
 [Fact]public void Rejects_incomplete_scan(){Assert.Throws<InvalidOperationException>(()=>AssessmentWorker.Normalize("<nmaprun/>"));}
 [Theory][InlineData("192.168.1.3",true)][InlineData("8.8.8.8",false)][InlineData("127.0.0.1",false)][InlineData("192.168.1.3;id",false)]public void Targets_are_literal_private_IPs(string ip,bool valid){Assert.Equal(valid,AssessmentGateway.PrivateIp(ip));}
}
