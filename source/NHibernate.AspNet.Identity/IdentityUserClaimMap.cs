using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNet.Identity
{
    public class IdentityUserClaimMap : ClassMapping<IdentityUserClaim>
    {
        public IdentityUserClaimMap()
        {
            Table("AspNetUserClaims");
            Id(x => x.Id, m => m.Generator(Generators.HighLow, g => g.Params(new
            {
                table = "KeyPool",
                column = "NextHigh",
                max_lo = 100,
                where = $"EntityName = '{nameof(IdentityUserClaim).ToLowerInvariant()}'"
            })));
            Property(x => x.ClaimType);
            Property(x => x.ClaimValue);

            ManyToOne(x => x.User, m => m.Column("UserId"));
        }
    }
}