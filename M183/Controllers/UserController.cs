using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace M183.Controllers
{
    public class UserController : Controller
    {
        // GET: User
        public ActionResult Dashboard()
        {
            var role = (string)Session["role"];
            if (role != "user")
            {
                return RedirectToAction("Login", "Home");
            }
            return View();
        }
    }
}