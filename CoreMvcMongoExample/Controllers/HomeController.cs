using CoreMvcMongoExample.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace CoreMvcMongoExample.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult PruebaError()
        {
            _logger.LogError("Prueba de error");
            return RedirectToAction("Index");
        }

        public IActionResult PruebaCritico()
        {
            _logger.LogCritical("Prueba de crítico");
            return RedirectToAction("Index");
        }

        public IActionResult PruebaWarning()
        {
            _logger.LogWarning("Prueba de warning");
            return RedirectToAction("Index");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
