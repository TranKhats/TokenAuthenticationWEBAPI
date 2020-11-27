﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TokenAuthenticationWEBAPI.Models;

namespace TokenAuthenticationWEBAPI.Models
{
    public class AuthenticationRepository : IDisposable
    {
        SECURITY_DBEntities context = new SECURITY_DBEntities();

        //Add the Refresh token
        public async Task<bool> AddRefreshToken(RefreshToken token)
        {
            var existingToken = context.RefreshTokens.FirstOrDefault(r => r.UserName == token.UserName
                            && r.ClientID == token.ClientID);

            if (existingToken != null)
            {
                var result = await RemoveRefreshToken(existingToken);
            }

            context.RefreshTokens.Add(token);
            int res = context.SaveChanges();
            return /*await context.SaveChangesAsync()*/res > 0;
        }

        //Remove the Refesh Token by id
        public async Task<bool> RemoveRefreshTokenByID(string refreshTokenId)
        {
            var refreshToken =  context.RefreshTokens.Find/*FindAsync*/(refreshTokenId);

            if (refreshToken != null)
            {
                context.RefreshTokens.Remove(refreshToken);
                int res = context.SaveChanges();
                return /*await context.SaveChangesAsync()*/res > 0;
                //return await context.SaveChangesAsync() > 0;
            }

            return false;
        }

        //Remove the Refresh Token
        public async Task<bool> RemoveRefreshToken(RefreshToken refreshToken)
        {
            context.RefreshTokens.Remove(refreshToken);
            int res = context.SaveChanges();
            return /*await context.SaveChangesAsync()*/res > 0;

            //return await context.SaveChangesAsync() > 0;
        }

        //Find the Refresh Token by token ID
        public async Task<RefreshToken> FindRefreshToken(string refreshTokenId)
        {
            var refreshToken = /*await*/ context.RefreshTokens.Find(refreshTokenId);
            return refreshToken;
        }

        //Get All Refresh Tokens
        public List<RefreshToken> GetAllRefreshTokens()
        {
            return context.RefreshTokens.ToList();
        }

        public void Dispose()
        {
            context.Dispose();
        }
    }
}