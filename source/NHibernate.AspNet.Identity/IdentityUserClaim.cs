using Microsoft.AspNetCore.Identity;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNet.Identity
{
    public class IdentityUserClaim : IdentityUserClaim<string>
    {
        public virtual IdentityUser User { get; set; }
    }

    public class IdentityUserClaimMap : ClassMapping<IdentityUserClaim>
    {
        public IdentityUserClaimMap()
        {
            Table("AspNetUserClaims");
            Id(x => x.Id, m => m.Generator(Generators.Identity));
            Property(x => x.ClaimType);
            Property(x => x.ClaimValue);

            ManyToOne(x => x.User, m => m.Column("UserId"));
        }
    }

}
