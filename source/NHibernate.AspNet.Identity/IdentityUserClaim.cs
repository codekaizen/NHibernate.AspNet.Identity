using Microsoft.AspNetCore.Identity;

namespace NHibernate.AspNet.Identity
{
    public class IdentityUserClaim : IdentityUserClaim<string>
    {
        public virtual IdentityUser User { get; set; }
    }
}
