using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNet.Identity.Tests.Models
{
    public class ApplicationUserMap : UnionSubclassMapping<ApplicationUser>
    {
        public ApplicationUserMap()
        {
            this.Extends(typeof(IdentityUser));
        }
    }
}