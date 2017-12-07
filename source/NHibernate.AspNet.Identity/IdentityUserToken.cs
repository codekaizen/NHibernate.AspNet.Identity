using System;
using Microsoft.AspNetCore.Identity;

namespace NHibernate.AspNet.Identity
{
    public class IdentityUserToken : IdentityUserToken<string>, IEquatable<IdentityUserToken<string>>
    {
        public bool Equals(IdentityUserToken<string> other)
        {
            if (other is null)
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return other.Name == this.Name && other.LoginProvider == this.LoginProvider && other.UserId == this.UserId;
        }
    }
}