using System.Threading.Tasks;
using System.Web.Mvc;
using MOCDIntegrations.Auth;
using Microsoft.Owin.Security;
using System.Web;
using System.Security.Claims;
using System.ComponentModel.DataAnnotations;

namespace MOCDIntegrations.Controllers
{
    public class AccountController : Controller
    {
        private readonly SqlServerAuthProvider _authProvider;

        public AccountController()
        {
            _authProvider = new SqlServerAuthProvider();
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Index", "Home");
            }
            
            // Limit the length of returnUrl to prevent issues with long URLs
            if (!string.IsNullOrEmpty(returnUrl) && returnUrl.Length > 200)
            {
                returnUrl = returnUrl.Substring(0, 200);
            }

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) && !returnUrl.StartsWith("/Account/Login"))
            {
                ViewBag.ReturnUrl = returnUrl;
            }
            else
            {
                ViewBag.ReturnUrl = Url.Action("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var identity = await _authProvider.AuthenticateUserAsync(model.Username, model.Password);

            if (identity == null)
            {
                ModelState.AddModelError("", "Invalid username or password.");
                return View(model);
            }

            var authenticationManager = HttpContext.GetOwinContext().Authentication;
            authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = model.RememberMe }, identity);

            // Limit the length of returnUrl to prevent issues with long URLs
            if (!string.IsNullOrEmpty(returnUrl) && returnUrl.Length > 200)
            {
                returnUrl = returnUrl.Substring(0, 200);
            }

            if (Url.IsLocalUrl(returnUrl) && !returnUrl.StartsWith("/Account/Login"))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        [HttpGet]
        public ActionResult SessionExpired()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            var authenticationManager = HttpContext.GetOwinContext().Authentication;
            authenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        public ActionResult UserProfile()
        {
            var user = (ClaimsIdentity)User.Identity;
            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var userRole = user.FindFirst(ClaimTypes.Role)?.Value;

            ViewBag.UserId = userId;
            ViewBag.UserRole = userRole;

            return View();
        }

        [HttpGet]
        public JsonResult CheckSessionStatus()
        {
            return Json(new { isAuthenticated = User.Identity.IsAuthenticated }, JsonRequestBehavior.AllowGet);
        }
    }

    public class LoginViewModel
    {
        [Required]
        [Display(Name = "Username")]
        public string Username { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
