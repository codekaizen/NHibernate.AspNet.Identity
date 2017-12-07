using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Identity;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

namespace NHibernate.AspNet.Identity
{
    public class IdentityUser : IdentityUser<string>
    {
        public virtual DateTime? LockoutEndDateUtc { get; set; }

        public virtual ICollection<IdentityRole> Roles { get; protected set; }

        public virtual ICollection<IdentityUserClaim> Claims { get; protected set; }

        public virtual ICollection<IdentityUserLogin> Logins { get; protected set; }

        public virtual ICollection<IdentityUserToken> Tokens { get; protected set; }

        public IdentityUser()
        {
        }

        public IdentityUser(string userName)
            : this()
        {
            this.UserName = userName;
        }

        public void AddToken(IdentityUserToken<string> token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            var userToken = new IdentityUserToken
            {
                UserId = token.UserId,
                Name = token.Name,
                LoginProvider = token.LoginProvider,
                Value = token.Value
            };

            EnsureTokensCollection();
            this.Tokens.Add(userToken);
        }

        public bool RemoveToken(IdentityUserToken<string> token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));

            var toRemove = this.Tokens?.SingleOrDefault(t => t.Equals(token));
            return toRemove != null && this.Tokens.Remove(toRemove);
        }

        private void EnsureTokensCollection()
        {
            if (this.Tokens == null)
            {
                this.Tokens = new List<IdentityUserToken>();
            }
        }

        internal void AddRole(IdentityRole roleEntity) => throw new NotImplementedException();
    }

    public class IdentityUserMap : ClassMapping<IdentityUser>
    {
        public IdentityUserMap()
        {
            this.Table("AspNetUsers");
            this.Id(x => x.Id, m => m.Generator(new UUIDHexCombGeneratorDef("D")));

            this.Property(x => x.AccessFailedCount);

            this.Property(x => x.Email);

            this.Property(x => x.EmailConfirmed);

            this.Property(x => x.LockoutEnabled);

            this.Property(x => x.LockoutEndDateUtc);

            this.Property(x => x.PasswordHash);

            this.Property(x => x.PhoneNumber);

            this.Property(x => x.PhoneNumberConfirmed);

            this.Property(x => x.TwoFactorEnabled);

            this.Property(x => x.UserName, map =>
            {
                map.Length(255);
                map.NotNullable(true);
                map.Unique(true);
            });

            this.Property(x => x.SecurityStamp);

            this.Bag(x => x.Claims, map =>
            {
                map.Key(k =>
                {
                    k.Column("UserId");
                    k.Update(false); // to prevent extra update after insert
                });
                map.Cascade(Cascade.All | Cascade.DeleteOrphans);
            }, rel => rel.OneToMany());

            this.Set(x => x.Logins, cam =>
            {
                cam.Table("AspNetUserLogins");
                cam.Key(km => km.Column("UserId"));
                cam.Cascade(Cascade.All | Cascade.DeleteOrphans);
            }, map =>
            {
                map.Component(comp =>
                {
                    comp.Property(p => p.LoginProvider);
                    comp.Property(p => p.ProviderKey);
                });
            });

            this.Bag(x => x.Roles, map =>
            {
                map.Table("AspNetUserRoles");
                map.Key(k => k.Column("UserId"));
            }, rel => rel.ManyToMany(p => p.Column("RoleId")));

            this.Bag(x => x.Tokens, map =>
            {
                map.Table("AspNetUserTokens");
                map.Key(k => k.Column("UserId"));
            }, rel => rel.OneToMany());
        }
    }
}