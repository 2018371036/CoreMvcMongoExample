using CoreMvcMongoExample.Models;
using CoreMvcMongoExample.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CoreMvcMongoExample.Controllers
{
    [Authorize]
    public class SubmissionController : Controller
    {
        private readonly SubmissionService _subSvc;
        private readonly ILogger _logger;

        public SubmissionController(SubmissionService submissionService, ILogger<SubmissionController> logger)
        {
            _subSvc = submissionService;
            _logger = logger;
        }

        [AllowAnonymous]
        public ActionResult<IList<Submission>> Index() => View(_subSvc.Read());

        [HttpGet]
        public ActionResult Create() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult<Submission> Create(Submission submission)
        {
            _logger.LogInformation("Creación de una nueva idea");
            submission.Created = submission.LastUpdated = DateTime.Now;
            submission.UserId = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;
            submission.UserName = User.Identity.Name;
            if (ModelState.IsValid)
            {
                _subSvc.Create(submission);
            }
            return RedirectToAction("Index");
        }

        [HttpGet]
        public ActionResult<Submission> Edit(string id) =>
            View(_subSvc.Find(id));

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(Submission submission)
        {
            _logger.LogInformation("Edición de una idea existente");
            submission.LastUpdated = DateTime.Now;
            submission.Created = submission.Created.ToLocalTime();
            if (ModelState.IsValid)
            {
                if (User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value != submission.UserId)
                {
                    return Unauthorized();
                }
                _subSvc.Update(submission);
                return RedirectToAction("Index");
            }
            return View(submission);
        }

        [HttpGet]
        public ActionResult Delete(string id)
        {
            _logger.LogInformation("Eliminación de una idea existente");
            _subSvc.Delete(id);
            return RedirectToAction("Index");
        }
    }
}
