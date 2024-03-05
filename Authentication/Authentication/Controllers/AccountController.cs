using Authentication.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Authentication.Controllers
{
    public class AccountController : Controller
    {
        // GET: AccountController
        public ActionResult Login(string accessToken="")
        {
            ViewBag.AccessToken = accessToken;
            return View(new LoginModel());
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult SubmitForm(LoginModel model)
        {
            if (Validateuser(model))
            {
                model.AccessToken = generateJwt();
                TempData["token"] = model.AccessToken;
                return RedirectToAction("Index", "Home");
            }
            else
            {
                model.AccessToken = "";
            }      
            return View("Login", model);
        }
        private bool Validateuser(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return false;
            }
            else
            {
                if (model.Username.Equals("sachin@gmail.com") && model.Password.Equals("sachin"))
                    return true;                   
            }
            return false;
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
