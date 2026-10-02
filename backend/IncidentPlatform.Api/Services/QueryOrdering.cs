using System.Linq.Expressions;

namespace IncidentPlatform.Api.Services;

/// <summary>
/// Shared sort helpers for list endpoints. Enums are persisted as strings, so a plain
/// ORDER BY on them is alphabetical ("Critical" &lt; "High" &lt; "Low" &lt; "Medium").
/// <see cref="ByEnumOrder"/> sorts by declaration order instead, translated by EF Core
/// into a SQL CASE expression.
/// </summary>
public static class QueryOrdering
{
    public static bool IsDescending(string? direction, bool defaultDescending) =>
        direction is null ? defaultDescending : direction.Equals("desc", StringComparison.OrdinalIgnoreCase);

    public static IOrderedQueryable<T> OrderBy<T, TKey>(this IQueryable<T> query, Expression<Func<T, TKey>> key, bool descending) =>
        descending ? query.OrderByDescending(key) : query.OrderBy(key);

    public static Expression<Func<T, int>> ByEnumOrder<T, TEnum>(Expression<Func<T, TEnum>> selector) where TEnum : struct, Enum
    {
        var values = Enum.GetValues<TEnum>();
        Expression body = Expression.Constant(values.Length);
        for (var i = values.Length - 1; i >= 0; i--)
        {
            body = Expression.Condition(
                Expression.Equal(selector.Body, Expression.Constant(values[i], typeof(TEnum))),
                Expression.Constant(i),
                body);
        }
        return Expression.Lambda<Func<T, int>>(body, selector.Parameters);
    }
}
