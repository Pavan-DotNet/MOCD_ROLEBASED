using System.Threading.Tasks;
using System.Web.Mvc;
using MOCDIntegrations.Auth;
using Microsoft.Owin.Security;
using System.Web;

namespace MOCDIntegrations.Controllers
{
    public class AccountController : Controller
    {
        private SqlServerAuthProvider _authProvider = new SqlServerAuthProvider();

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
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

            var authManager = HttpContext.GetOwinContext().Authentication;
            authManager.SignIn(new AuthenticationProperties { IsPersistent = model.RememberMe }, identity);

            return RedirectToLocal(returnUrl);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            var authManager = HttpContext.GetOwinContext().Authentication;
            authManager.SignOut("ApplicationCookie");
            return RedirectToAction("Index", "Home");
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }
    }

    public class LoginViewModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public bool RememberMe { get; set; }
    }
}
