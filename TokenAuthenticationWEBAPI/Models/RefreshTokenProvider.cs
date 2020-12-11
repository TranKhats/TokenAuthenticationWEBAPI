using System;
using Microsoft.Owin.Security.Infrastructure;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace TokenAuthenticationWEBAPI.Models
{
    public class RefreshTokenProvider : IAuthenticationTokenProvider
    {
        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            //Get the client ID from the Ticket properties
            var clientid = context.Ticket.Properties.Dictionary["client_id"];
            if (string.IsNullOrEmpty(clientid))
            {
                return;
            }
            //Generating a Uniqure Refresh Token ID
            var refreshTokenId = Guid.NewGuid().ToString("n");
            using (AuthenticationRepository _repo = new AuthenticationRepository())
            {
                // Getting the Refesh Token Life Time From the Owin Context
                var refreshTokenLifeTime = context.OwinContext.Get<string>("ta:clientRefreshTokenLifeTime");
                //Creating the Refresh Token object
                var token = new RefreshToken()
                {
                    //storing the RefreshTokenId in hash format
                    ID = Helper.GetHash(refreshTokenId),
                    ClientID = clientid,
                    UserName = context.Ticket.Identity.Name,
                    IssuedTime = DateTime.UtcNow,
                    ExpiredTime = DateTime.UtcNow.AddMinutes(Convert.ToDouble(refreshTokenLifeTime))
                };
                //Setting the Issued and Expired time of the Refresh Token
                context.Ticket.Properties.IssuedUtc = token.IssuedTime;
                context.Ticket.Properties.ExpiresUtc = token.ExpiredTime;
                token.ProtectedTicket = context.SerializeTicket();
                var result = await _repo.AddRefreshToken(token);

                if (result)
                {
                    context.SetToken(refreshTokenId);
                }
            }
        }
        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
            //var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            //context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            string hashedTokenId = Helper.GetHash(context.Token);
            

            using (SECURITY_DBEntities dbContext = new SECURITY_DBEntities())
            {
                //var refreshToken = await _repo.FindRefreshToken(hashedTokenId);
                var refreshToken = dbContext.RefreshTokens.Find(hashedTokenId);

                if (refreshToken != null)
                {
                    //Get protectedTicket from refreshToken class
                    context.DeserializeTicket(refreshToken.ProtectedTicket);
                    //var result = await _repo.RemoveRefreshToken(hashedTokenId);
                }
            }
            if (context.Ticket == null)
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                context.Response.ReasonPhrase = "invalid token";
                return;
            }

            if (context.Ticket.Properties.ExpiresUtc <= DateTime.UtcNow)
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                context.Response.ReasonPhrase = "unauthorized";
                return;
            }

            context.Ticket.Properties.ExpiresUtc = DateTime.UtcNow.AddDays(5);
            context.SetTicket(context.Ticket);
        }
        public void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }
        public void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }
    }
}