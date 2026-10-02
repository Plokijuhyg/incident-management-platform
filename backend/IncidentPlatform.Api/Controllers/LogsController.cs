using IncidentPlatform.Api.DTOs.Common;
using IncidentPlatform.Api.DTOs.Logs;
using IncidentPlatform.Api.Models;
using IncidentPlatform.Api.Services.Ingestion;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/logs")]
public sealed class LogsController : ControllerBase
{
    private readonly ILogIngestionService _ingestion;
    private readonly ILogQueryService _query;

    public LogsController(ILogIngestionService ingestion, ILogQueryService query)
    {
        _ingestion = ingestion;
        _query = query;
    }

    // Anonymous + pre-shared ingest key (LogIngestAccess): forwarders cannot carry a JWT.
    [HttpPost("ingest")]
    [AllowAnonymous]
    [ServiceFilter(typeof(LogIngestAccess))]
    [RequestSizeLimit(16 * 1024 * 1024)]
    public async Task<ActionResult<IngestResponse>> Ingest([FromBody] IngestRequest request, CancellationToken cancellationToken)
    {
        var result = await _ingestion.IngestAsync(request.Source.Trim(), request.Format, request.Lines, cancellationToken);
        return Ok(new IngestResponse(result.Accepted, result.Duplicates, result.Alerts, result.Blank));
    }

    [HttpGet]
    [Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager}")]
    public async Task<ActionResult<PagedResult<LogSummaryResponse>>> GetPaged([FromQuery] LogQuery query, CancellationToken cancellationToken)
    {
        return Ok(await _query.GetPagedAsync(query, cancellationToken));
    }

    [HttpGet("summary")]
    [Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager}")]
    public async Task<ActionResult<LogSummaryStats>> Summary(CancellationToken cancellationToken)
    {
        return Ok(await _query.GetSummaryAsync(cancellationToken));
    }

    [HttpGet("{id:long}")]
    [Authorize(Roles = $"{RoleNames.Admin},{RoleNames.SecurityManager}")]
    public async Task<ActionResult<LogDetailResponse>> GetById(long id, CancellationToken cancellationToken)
    {
        return Ok(await _query.GetByIdAsync(id, cancellationToken));
    }
}
