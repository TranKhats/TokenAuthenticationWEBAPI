using System;
using Microsoft.Owin.Security.Infrastructure;
using System.Threading.Tasks;

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
        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
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