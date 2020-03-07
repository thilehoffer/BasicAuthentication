using BasicAuth.App;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace BasicAuth.Handlers
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IOptions<ConfigItems> _config;

        public BasicAuthenticationHandler(
            IOptions<ConfigItems>config,
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock
            ) : base(options, logger, encoder, clock) {

            _config = config;
        
        }
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
             
            //dG9kZGhpbGVob2ZmZXJAeWFob28uY29tOkZha2UkI1Bhc3N3b3Jk  Encypted from https://www.base64encode.org/
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Authorization header was not found");

            var authHeaderValue = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);

            if (string.Equals(authHeaderValue.Parameter, _config.Value.ApiKey)){
                var claims = new[] { new Claim(ClaimTypes.Name, _config.Value.ApiKey) };
                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principal = new ClaimsPrincipal(identity);
                return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
            }
            else {
                return AuthenticateResult.Fail("Not Authorized");
            }
             
        }
    }
}
