using Authentication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace Authentication.Controllers
{
    public class ApplicationUser : IdentityUser
    {
        // Additional properties can be added here if needed
        // For example, FirstName, LastName, etc.
    }
    [RequireHttps]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        public async Task<IActionResult> Index()
        {
            ViewBag.Token = TempData["token"];
            return View();
        }
        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
        private string generateJwt()
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("aWK62lOXkrMJYDdsMDFkKrX8bOh09N6fnsOgqOFZRCY"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            //If you've had the login module, you can also use the real user information here
            var claims = new[] {
        new Claim(JwtRegisteredClaimNames.Sub, "user_name"),
        new Claim(JwtRegisteredClaimNames.Email, "user_email"),
        new Claim("DateOfJoing", "2022-09-12"),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

            var token = new JwtSecurityToken("Test.com",
                "Test.com",
                claims,
                expires: DateTime.Now.AddMinutes(120),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
