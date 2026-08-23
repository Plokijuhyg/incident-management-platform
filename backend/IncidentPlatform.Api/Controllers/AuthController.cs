using IncidentPlatform.Api.DTOs.Auth;
using IncidentPlatform.Api.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace IncidentPlatform.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("login")]
    public async Task<ActionResult<LoginResponse>> Login(
        [FromBody] LoginRequest request,
        CancellationToken cancellationToken)
    {
        // No try/catch here — AuthenticationFailedException (and any other
        // AppException) propagates up to GlobalExceptionHandler, which maps
        // it to the correct status code. The controller stays exactly as
        // thin as architecture.md §2 requires: bind, call one service
        // method, return.
        var result = await _authService.LoginAsync(request, cancellationToken);
        return Ok(result);
    }
}
