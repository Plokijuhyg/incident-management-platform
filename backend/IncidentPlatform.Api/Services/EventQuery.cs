using System.Linq.Expressions;
using System.Text.Json;
using System.Text.RegularExpressions;
using IncidentPlatform.Api.Models;
namespace IncidentPlatform.Api.Services;

// Small parameterized query language; never accepts SQL or dynamic property execution.
public static class EventQuery
{
    public static IQueryable<WindowsEvent> Apply(IQueryable<WindowsEvent> query,string? text)
    {
        if(string.IsNullOrWhiteSpace(text))return query;
        if(text.Length>2000)throw new ArgumentException("Query is limited to 2000 characters.");
        var parser=new Parser(text);return query.Where(parser.Parse());
    }
    private sealed class Parser
    {
        private readonly List<string> tokens=[];private int index;private int terms;
        private readonly ParameterExpression row=Expression.Parameter(typeof(WindowsEvent),"e");
        public Parser(string text)
        {
            var regex=new Regex("\\G\\s*(\"(?:[^\"\\\\]|\\\\.)*\"|>=|<=|!=|!~|[=~<>()]|[^\\s=~<>!()]+)",RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(50));
            int pos=0;
            while(pos<text.Length && !string.IsNullOrWhiteSpace(text[pos..]))
            {var m=regex.Match(text,pos);if(!m.Success)throw new ArgumentException("Invalid query syntax. Quote values containing spaces.");tokens.Add(m.Groups[1].Value);pos=m.Index+m.Length;}
            if(tokens.Count>256)throw new ArgumentException("Query is too complex.");
        }
        private bool Take(string value){if(index<tokens.Count && tokens[index].Equals(value,StringComparison.OrdinalIgnoreCase)){index++;return true;}return false;}
        private string Next()=>index<tokens.Count?tokens[index++]:throw new ArgumentException("Incomplete query.");
        public Expression<Func<WindowsEvent,bool>> Parse(){var expression=Or(0);if(index!=tokens.Count)throw new ArgumentException("Expected AND or OR between conditions.");return Expression.Lambda<Func<WindowsEvent,bool>>(expression,row);}
        private Expression Or(int depth){var left=And(depth);while(Take("OR"))left=Expression.OrElse(left,And(depth));return left;}
        private Expression And(int depth){var left=Atom(depth);while(Take("AND"))left=Expression.AndAlso(left,Atom(depth));return left;}
        private Expression Atom(int depth)
        {
            if(depth>10)throw new ArgumentException("Query nesting is limited to 10 levels.");
            if(Take("NOT"))return Expression.Not(Atom(depth+1));
            if(Take("(")){var node=Or(depth+1);if(!Take(")"))throw new ArgumentException("Missing closing parenthesis.");return node;}
            if(++terms>64)throw new ArgumentException("Query is limited to 64 conditions.");
            var name=Next().ToLowerInvariant();var op=Next();var raw=Next();
            string value;
            try{value=raw.StartsWith('"')?JsonSerializer.Deserialize<string>(raw)!:raw;}catch(JsonException){throw new ArgumentException("Invalid quoted value.");}
            var property=name switch {"eventid"=>"EventId","level"=>"Level","id"=>"Id","machine" or "host"=>"Machine","channel"=>"Channel","provider"=>"Provider","message"=>"Message",_=>throw new ArgumentException("Unknown field. Use eventId, level, id, machine, channel, provider or message.")};
            var member=Expression.Property(row,property);
            if(member.Type==typeof(string))
            {
                var constant=Expression.Constant(value);
                return op switch {"="=>Expression.Equal(member,constant),"!="=>Expression.NotEqual(member,constant),"~"=>Expression.Call(member,nameof(string.Contains),Type.EmptyTypes,constant),"!~"=>Expression.Not(Expression.Call(member,nameof(string.Contains),Type.EmptyTypes,constant)),_=>throw new ArgumentException("Text fields support =, !=, ~ (contains) and !~.")};
            }
            if(!long.TryParse(value,out var numeric) || member.Type==typeof(int) && (numeric<int.MinValue || numeric>int.MaxValue))throw new ArgumentException("Numeric field requires an integer.");
            var number=Expression.Constant(member.Type==typeof(int)?(object)(int)numeric:numeric,member.Type);
            return op switch {"="=>Expression.Equal(member,number),"!="=>Expression.NotEqual(member,number),">"=>Expression.GreaterThan(member,number),">="=>Expression.GreaterThanOrEqual(member,number),"<"=>Expression.LessThan(member,number),"<="=>Expression.LessThanOrEqual(member,number),_=>throw new ArgumentException("Invalid numeric operator.")};
        }
    }
}
