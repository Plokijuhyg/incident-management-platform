using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services;
namespace IncidentPlatform.Tests;
public class EventQueryTests
{
    private static IQueryable<WindowsEvent> Events()=>new[]{new WindowsEvent{Id=1,EventId=4625,Channel="Security",Machine="PC",Level=2,Message="failed login"},new WindowsEvent{Id=2,EventId=7045,Channel="System",Machine="LAB",Level=4,Message="service installed"}}.AsQueryable();
    [Fact] public void Boolean_precedence_parentheses_numeric_comparisons_and_quoted_text_work()
    {
        Assert.Single(EventQuery.Apply(Events(),"eventId = 4625 AND (channel = Security OR machine = LAB)"));
        Assert.Equal(2,EventQuery.Apply(Events(),"eventId >= 4000 AND NOT level > 4").Count());
        Assert.Equal(1,EventQuery.Apply(Events(),"message ~ \"failed login\" AND id != 2").Single().Id);
    }
    [Theory]
    [InlineData("eventId = 1; DROP TABLE Alerts")]
    [InlineData("eventId = banana")]
    [InlineData("password = anything")]
    [InlineData("(eventId = 1")]
    [InlineData("eventId = 1 OR")]
    public void Invalid_queries_fail_with_a_validation_error(string query)=>Assert.Throws<ArgumentException>(()=>EventQuery.Apply(Events(),query));
}
