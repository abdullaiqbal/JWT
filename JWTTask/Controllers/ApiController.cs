using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JWTTask.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ApiController : ControllerBase
    {
        
        [Authorize]
        [HttpGet("getWithAny")]
        public IActionResult GetWithAny()
        {
            return Ok(new { Message = $"Hello {GetUsername()}" });
        }

        [Authorize(Policy = "OnlySecondJwtScheme")]
        [HttpGet("getWithSecondJwt")]
        public IActionResult GetWithSecondJwt()
        {
            return Ok(new { Message = $"Hello {GetUsername()} with Second JWT" });
        }

        [Authorize(Policy = "OnlyCookieScheme")]
        [HttpGet("getWithCookie")]
        public IActionResult GetWithCookie()
        {
            var userName = HttpContext.User.Claims
                    .Where(x => x.Type == ClaimTypes.Name)
                    .Select(x => x.Value)
                    .FirstOrDefault();
            return Content($"<p>Hello {userName} With Cookie</p>");
        }


        [Authorize]
        [HttpGet("getWithMultiple")]
        public IActionResult GetWithMultiple()
        {
            return Ok(new { Message = $"Hello {GetUsername()}" });
        }

        private string? GetUsername()
        {
            return HttpContext.User.Claims
                .Where(x => x.Type == ClaimTypes.Name)
                .Select(x => x.Value)
                .FirstOrDefault();
        }
    }
}
