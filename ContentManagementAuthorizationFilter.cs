using Microsoft.Extensions.DependencyInjection;
using Sitecore.DependencyInjection;
using Sitecore.Diagnostics;
using Sitecore.Services.Core.Diagnostics;
using Sitecore.Services.Infrastructure.Net.Http;
using Sitecore.Services.Infrastructure.Web.Http.Filters;
using System;
using System.Net;
using System.Net.Http;
using System.Web.Http.Controllers;

namespace HelixBase.Foundation.Services.Infrastructure.Security
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class ContentManagementAuthorizationFilter : AuthorizationFilterBase
    {
        public ContentManagementAuthorizationFilter() : this(ServiceLocator.ServiceProvider.GetService<ILogger>(),
            ServiceLocator.ServiceProvider.GetService<IRequestOrigin>())
        {

        }

        public ContentManagementAuthorizationFilter(ILogger logger, IRequestOrigin requestOrigin) : base(logger, requestOrigin)
        {
        }

        protected override void DoAuthorization(HttpActionContext actionContext)
        {
            Assert.ArgumentNotNull((object)actionContext, nameof(actionContext));

            if (IsAuthorized(actionContext)) 
                return;

            this.LogUnauthorizedRequest(actionContext.Request, "Content Delivery doesn't not have access to this request.");
            actionContext.Response = actionContext.Request.CreateResponse(HttpStatusCode.Forbidden);
        }

        public bool IsAuthorized(HttpActionContext actionContext)
        {
            if (Sitecore.Context.Database.Name != "master")
                return true;

            return !actionContext.Request.Method.Equals(HttpMethod.Post)
                   && !actionContext.Request.Method.Equals(HttpMethod.Put)
                   && !actionContext.Request.Method.Equals(HttpMethod.Delete);
        }
    }
}
