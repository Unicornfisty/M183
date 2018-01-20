using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace M183.Controllers
{
    public class AdminController : Controller
    {
        // GET: Admin
        public ActionResult Dashboard()
        {
            var role = (string)Session["role"];
            if (role != "admin")
            {
                return RedirectToAction("Login", "Home");
            }
            return View();
        }
    }
}