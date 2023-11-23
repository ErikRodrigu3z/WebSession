using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity;
using System.Web;
using System.Web.Mvc;
using WebTest.Models;

namespace WebTest.Controllers
{
    public class CustomAuthorizeAttribute : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {          
            bool _isAuthorized = false;
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));
            // Verifica si la cookie de sesión almacenada coincide con la actual
            var storedSessionId = httpContext.Request.Cookies["MyAppSessionId"]?.Value;
            
            if (httpContext.User.Identity.IsAuthenticated)
            {
                var user = userManager.FindByName(httpContext.User.Identity.Name);  
                
                //Validate user and rol
                if (!string.IsNullOrEmpty(base.Roles))
                {
                    foreach (var rol in base.Roles.Split(','))
                    {

                        if (userManager.IsInRole(userManager.FindByName(httpContext.User.Identity.Name).Id, rol) && 
                            user.SessionID == storedSessionId)
                        {
                            _isAuthorized = true;
                        }                        
                    }
                }
                else //if _roles is null, the end point only vaidate if user Is Authenticated and SessionID is the same
                {
                    return user.SessionID == storedSessionId;
                }               
            }
            return _isAuthorized;
        }

        protected override void HandleUnauthorizedRequest(AuthorizationContext filterContext)
        {
            // Manejo personalizado para solicitudes no autorizadas, si es necesario.
            // Por ejemplo, redirige a una página de acceso denegado.

            filterContext.Result = new HttpUnauthorizedResult("Acceso denegado. Mensaje personalizado.");
        }



    }
}