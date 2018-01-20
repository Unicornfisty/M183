using M183.Models;
using Nexmo.Api;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace M183.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        public ActionResult Login()
        {
            return View();
        }

        public ActionResult Logs()
        {
            SqlConnection con = new SqlConnection();
            con.ConnectionString = "Data Source=(LocalDB)\\MSSQLLocalDB;AttachDbFilename=C:\\VS\\M183\\Ressourcen_Projekt\\m183_project.mdf;" +
                "Integrated Security=True;Connect Timeout=30";

            // check the credentails from the database - caution: SQL Injection should be prevented additionally!
            SqlCommand cmd_credentials = new SqlCommand();
            cmd_credentials.CommandText = "SELECT * FROM [dbo].[UserLog] ul JOIN [dbo].[User] u ON ul.UserId = u.Id ORDER BY ul.CreatedOn DESC";
            cmd_credentials.Connection = con;

            con.Open();

            SqlDataReader reader = cmd_credentials.ExecuteReader();

            if (reader.HasRows) // ok - result was found
            {
                // map the db-results into a list so razor can iterate over the results
                List<HomeControllerViewModel> model = new List<HomeControllerViewModel>();
                while (reader.Read())
                {
                    var log_entry = new HomeControllerViewModel(); // custom created view model

                    // 0 = LogId, 1 = UserId, 2 = IP
                    // 3 = Browser 4 = Action, 5 = Result, 6 = AdditionalInformation
                    // 7 = CreatedOn, 8 = ModifiedOn, 9 = Deletedon
                    // 10 = Id, 11 = Username, 12 = Password

                    log_entry.UserId = reader.GetValue(10).ToString();
                    log_entry.LogId = reader.GetValue(0).ToString();
                    log_entry.LogCreatedOn = reader.GetValue(7).ToString();
                    // to be continued ...

                    model.Add(log_entry);
                }

                return View(model);

            }
            else
            {
                ViewBag.message = "No Results found";
                return View();
            }
        }

        [HttpPost]
        public ActionResult DoLogin()
        {
            // get login-form-data
            var username = Request["username"];
            var password = Request["password"];

            // get additional infos about the request - if set properly by client.
            var ip = Request.ServerVariables["REMOTE_ADDR"];
            var platform = Request.Browser.Platform;
            var browser = Request.UserAgent;

            // connection to database
            SqlConnection con = new SqlConnection();
            con.ConnectionString = "Data Source=(LocalDB)\\MSSQLLocalDB;AttachDbFilename=C:\\VS\\M183\\Ressourcen_Projekt\\m183_project.mdf;" +
                "Integrated Security=True;Connect Timeout=30";

            // check the credentails from the database - caution: SQL Injection should be prevented additionally!
            SqlCommand cmd_credentials = new SqlCommand();
            cmd_credentials.CommandText = "SELECT [Id], [Username], [Role], [Status], [Mobilephonenumber] FROM [dbo].[User] WHERE [Username] = '" + username + "' AND [Password] = '" + password + "'";
            cmd_credentials.Connection = con;

            con.Open();

            SqlDataReader reader_credentials = cmd_credentials.ExecuteReader();

            if (reader_credentials.HasRows || (string)Session["TwoFactorOk"] == "true") // ok - result was found
            {
                Session["username"] = username;
                var user_id = 0;
                
                while (reader_credentials.Read())
                {
                    user_id = reader_credentials.GetInt32(0); // get the user id
                    Session["userid"] = user_id;
                }
                if ((string)Session["TwoFactorOk"] == null)
                {
                    con.Close();
                    //Change to db number
                    return Check2Factor("+41787791910", user_id, username, password);
                }
                con.Close();
            }
            else
            {
                // credentials do not match 
                // check whether a user can be found at least upon username

                con.Close();
                con.Open();

                SqlCommand cmd_userid_by_name = new SqlCommand();

                cmd_userid_by_name.CommandText = "SELECT [Id] FROM [dbo].[User] WHERE [Username] = '" + username + "'";
                cmd_userid_by_name.Connection = con;

                SqlDataReader reader_userid_by_name = cmd_userid_by_name.ExecuteReader();

                if (reader_userid_by_name.HasRows) // user has been found
                {
                    var user_id = 0;
                    while (reader_credentials.Read())
                    {
                        user_id = reader_credentials.GetInt32(0); // get the user id
                        break;
                    }

                    con.Close();
                    con.Open();

                    // check, whether user has already 5 login attempts
                    // or password does by far not match the systems reccommendations
                    // => Block the user
                    SqlCommand failed_log_cmd = new SqlCommand();
                    failed_log_cmd.CommandText = "SELECT COUNT(ID) FROM [dbo].[UserLog] WHERE UserId = '" + user_id + "' " +
                        "AND Result = 'failed' AND CAST(CreatedOn As date) = '" + System.DateTime.Now.ToShortDateString().Substring(0, 10) + "'";
                    failed_log_cmd.Connection = con;
                    SqlDataReader failed_login_count = failed_log_cmd.ExecuteReader();

                    var attempts = 0;
                    if (failed_login_count.HasRows)
                    {
                        while (reader_credentials.Read())
                        {
                            attempts = reader_credentials.GetInt32(0); // get the count
                            break;
                        }
                    }

                    con.Close();
                    con.Open();
                    if (attempts >= 3 || password.Length < 4 || password.Length > 20) // depends on the application context!
                    {
                        SqlCommand block_cmd = new SqlCommand();
                        block_cmd.CommandText = "UPDATE [dbo].[User] SET [Status] = 'Blocked' WHERE [Id] = '" + user_id.ToString() + "'";
                        block_cmd.Connection = con;
                        block_cmd.ExecuteReader();
                    }
                    con.Close();
                    con.Open();

                    // log behaviour anyway
                    // log this user-behaviour anyway
                    SqlCommand log_cmd = new SqlCommand();
                    log_cmd.CommandText = "INSERT INTO [dbo].[UserLog] (UserId, IP, Action, Result, CreatedOn, Browser) " +
                        "VALUES('" + user_id + "', '" + ip + "', 'login', 'failed', GETDATE(), '" + platform + "')";
                    log_cmd.Connection = con;
                    log_cmd.ExecuteReader();

                    ViewBag.Message = "No user found";
                }
                else
                {
                    con.Close();
                    con.Open();

                    // not even the username is correct!
                    // log it with user_id = 0
                    // log this user-behaviour anyway
                    SqlCommand log_cmd = new SqlCommand();
                    log_cmd.CommandText = "INSERT INTO [dbo].[UserLog] (UserId, IP, Action, Result, CreatedOn, AdditionalInformation, Browser) " +
                        "VALUES(3, '" + ip + "', 'login', 'failed', GETDATE(), 'No User Found', '" + platform + "')";
                    log_cmd.Connection = con;
                    log_cmd.ExecuteReader();

                    ViewBag.Message = "No user found";
                }
            }

            con.Close();

            return RedirectToAction("Login", "Home");
        }

        public ActionResult Logout()
        {
            Session.Clear();
            return RedirectToAction("Index");
        } 

        public ActionResult Check2Factor(string to, int userId, string username, string password)
        {
            SqlConnection con = new SqlConnection();
            con.ConnectionString = "Data Source=(LocalDB)\\MSSQLLocalDB;AttachDbFilename=C:\\VS\\M183\\Ressourcen_Projekt\\m183_project.mdf;" +
                "Integrated Security=True;Connect Timeout=30";

            var request = (HttpWebRequest)WebRequest.Create("https://rest.nexmo.com/sms/json");

            var secret = "1234";

            var postData = "api_key=4de9ebde";
            postData += "&api_secret=b4a730dd9192692e";
            postData += "&to="+to;
            postData += "&from=\"\"NEXMO\"\"";
            postData += "&text=\"" + secret + "\"";
            var data = Encoding.ASCII.GetBytes(postData);

            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = data.Length;

            using (var stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }

            var response = (HttpWebResponse)request.GetResponse();

            var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
            //con.Open();

            //// not even the username is correct!
            //// log it with user_id = 0
            //// log this user-behaviour anyway
            //double time = 5;
            //SqlCommand log_cmd = new SqlCommand();
            //log_cmd.CommandText = "INSERT INTO [dbo].[Token] (Token, UserId, Expiry) " +
            //    "VALUES('" + secret + "', " + userId + ", '" + (DateTime.Now.AddMinutes(time)) + "')";
            //log_cmd.Connection = con;
            //log_cmd.ExecuteReader();

            ////con.Close();
            ViewBag.username = username;
            ViewBag.password = password;
            Session["Token"] = secret;
            return RedirectToAction("TokenLogin", "Home");
        }

        public ActionResult TokenLogin()
        {
            return View();
        }

        [HttpPost]
        public ActionResult DoCheckTwoFactor()
        {
            var username = Request["username"];
            var password = Request["password"];
            var code = Request["token"];

            SqlConnection con = new SqlConnection();
            con.ConnectionString = "Data Source=(LocalDB)\\MSSQLLocalDB;AttachDbFilename=C:\\VS\\M183\\Ressourcen_Projekt\\m183_project.mdf;" +
                "Integrated Security=True;Connect Timeout=30";
            //con.Open();

            //// check, whether user has already 5 login attempts
            //// or password does by far not match the systems reccommendations
            //// => Block the user
            //SqlCommand check = new SqlCommand();
            //check.CommandText = "SELECT [Id], [Token], [UserId], [Expiry], [DeletedOn] FROM [dbo].[Token] WHERE UserId = ";
            //check.Connection = con;
            //SqlDataReader failed_login_count = check.ExecuteReader();

            if ((string)Session["Token"] == code)
            {
                Session["TwoFactorOk"] = "true";
                ViewBag.username = username;
                ViewBag.password = password;

                SqlCommand cmd_credentials = new SqlCommand();
                cmd_credentials.CommandText = "SELECT [Id], [Username], [Role], [Status], [Mobilephonenumber] FROM [dbo].[User] WHERE [Username] = '" + username + "' AND [Password] = '" + password + "'";
                cmd_credentials.Connection = con;

                con.Open();

                SqlDataReader reader_credentials = cmd_credentials.ExecuteReader();
                string status = "";
                string role = "";

                while (reader_credentials.Read())
                {
                    role = reader_credentials.GetString(2);
                    status = reader_credentials.GetString(3);
                }

                if (status != "blocked")
                {
                    if (role == "admin")
                    {
                        Session["role"] = "admin";
                        con.Close();
                        return RedirectToAction("Dashboard", "Admin");
                    }
                    else if (role == "user")
                    {
                        Session["role"] = "user";
                        con.Close();
                        return RedirectToAction("Dashboard", "User");
                    }
                }
                ViewBag.Message = "You are currently blocked!";
                con.Close();
            }
            else
            {
                Session["TwoFactorOk"] = "false";
            }
            return RedirectToAction("Login", "Home");
        }
    }
}