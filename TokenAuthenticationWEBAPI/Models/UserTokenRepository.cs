﻿using System;
using System.Linq;

namespace TokenAuthenticationWEBAPI.Models
{
    class UserTokenRepository : IDisposable
    {
        // Test_DBEntities it is your context class
        SECURITY_DBEntities context = new SECURITY_DBEntities();

        public Token GetTokenFromDB(string username, string password)
        {
            UserTokenMaster userMaster = context.UserTokenMasters.FirstOrDefault(user =>
            user.UserName.Equals(username, StringComparison.OrdinalIgnoreCase)
            && user.UserPassword == password);
            Token token = null;

            if (userMaster != null)
            {
                token = new Token()
                {
                    AccessToken = userMaster.AccessToken,
                    RefreshToken = userMaster.RefreshToken,
                    ExpiredDateTime = (DateTime)userMaster.TokenExpiredTime
                };
            }

            return token;
        }

        //Adding Token into the DB
        public bool AddUserTokenIntoDB(UserTokenMaster userTokenMaster)
        {
            //First Check the existance of the Token in the DB
            var tokenMaster = context.UserTokenMasters.FirstOrDefault(x => x.UserName == userTokenMaster.UserName
                            && x.UserPassword == userTokenMaster.UserPassword);
            if (tokenMaster != null)
            {
                context.UserTokenMasters.Remove(tokenMaster);
            }

            context.UserTokenMasters.Add(userTokenMaster);

            bool isAdded = context.SaveChanges() > 0;
            return isAdded;
        }

        public void Dispose()
        {
            context.Dispose();
        }
    }
}