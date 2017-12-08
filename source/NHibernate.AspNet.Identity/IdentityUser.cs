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

        public virtual void AddToken(IdentityUserToken<string> token)
        {
            EnsureTokensCollection();
            AddToCollection<IdentityUserToken>(this.Tokens, token);
        }

        public virtual bool RemoveToken(IdentityUserToken<string> token)
        {
            return RemoveFromCollection(this.Tokens, token);
        }

        public virtual void AddRole(IdentityRole role)
        {
            EnsureRolesCollection();
            AddToCollection(this.Roles, role);
        }

        public virtual bool RemoveRole(IdentityRole role)
        {
            return RemoveFromCollection(this.Roles, role);
        }

        public virtual void AddClaim(IdentityUserClaim claim)
        {
            EnsureClaimsCollection();
            AddToCollection(this.Claims, claim);
        }

        public virtual bool RemoveClaim(IdentityUserLogin claim)
        {
            return RemoveFromCollection(this.Claims, claim);
        }

        public virtual void AddLogin(IdentityUserLogin login)
        {
            EnsureLoginsCollection();
            AddToCollection(this.Logins, login);
        }

        public virtual bool RemoveLogin(IdentityUserLogin login)
        {
            RemoveFromCollection(this.Logins, login);
        }

        private void EnsureLoginsCollection()
        {
            if (this.Logins == null)
            {
                this.Logins = new List<IdentityUserLogin>();
            }
        }

        private void EnsureTokensCollection()
        {
            if (this.Tokens == null)
            {
                this.Tokens = new List<IdentityUserToken>();
            }
        }

        private void EnsureRolesCollection()
        {
            if (this.Roles == null)
            {
                this.Roles = new List<IdentityRole>();
            }
        }

        private void EnsureClaimsCollection()
        {
            if (this.Claims == null)
            {
                this.Claims = new List<IdentityUserClaim>();
            }
        }

        private void AddToCollection<T>(ICollection<T> collection, T item)
        {
            if (collection == null)
                throw new ArgumentNullException(nameof(collection));
            if (item == null)
                throw new ArgumentNullException(nameof(item));

            if (!collection.Contains(item))
            {
                collection.Add(item);
            }
        }

        private bool RemoveFromCollection<T>(ICollection<T> collection, T item)
            where T : class
        {
            if (item == null)
                throw new ArgumentNullException(nameof(item));

            var toRemove = collection?.SingleOrDefault(i => i.Equals(item));
            return toRemove != null && (collection?.Remove(toRemove)).GetValueOrDefault();
        }
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