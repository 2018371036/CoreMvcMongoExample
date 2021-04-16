using CoreMvcMongoExample.Models;
using CoreMvcMongoExample.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace CoreMvcMongoExample
{
    public class Startup
    {
        private readonly ILogger _logger = LoggerFactory.Create(builder => builder.AddLog4Net()).CreateLogger<Startup>();

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging();
            services.AddSingleton<ILoggerFactory, LoggerFactory>();
            services.AddSingleton(typeof(ILogger<>), typeof(Logger<>));
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.Authority = Configuration["Okta:Domain"] + "/oauth2/default";
                options.RequireHttpsMetadata = true;
                options.ClientId = Configuration["Okta:ClientId"];
                options.ClientSecret = Configuration["Okta:ClientSecret"];
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.SaveTokens = true;
                options.Events.OnUserInformationReceived = ctx =>
                {
                    _logger.LogInformation("SESIÓN INICIADA A LAS " + DateTime.Now.ToString());
                    return Task.CompletedTask;
                };
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "groups",
                    ValidateIssuer = true
                };
            });

            services.AddAuthorization();
            services.AddControllersWithViews();
            services.Configure<DatabaseSettings>(Configuration.GetSection(nameof(DatabaseSettings)));
            services.AddSingleton<IDatabaseSettings>(x => x.GetRequiredService<IOptions<DatabaseSettings>>().Value);
            services.AddSingleton<SubmissionService>();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
