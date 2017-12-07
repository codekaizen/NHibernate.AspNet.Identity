using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using NHibernate.AspNet.Identity.Properties;
using NHibernate.Linq;

namespace NHibernate.AspNet.Identity
{
    /// <summary>
    /// Implements IUserStore using NHibernate where TUser is the entity type of the user being stored
    /// </summary>
    /// <typeparam name="TUser"/>
    public class UserStore<TUser> : UserStoreBase<TUser, string, IdentityUserClaim, IdentityUserLogin, IdentityUserToken<string>>, IUserRoleStore<TUser>
        where TUser : IdentityUser
    {
        /// <summary>
        /// If true then disposing this object will also dispose (close) the session. False means that external code is responsible for disposing the session.
        /// </summary>
        public bool ShouldDisposeSession { get; set; }

        public ISession Context { get; private set; }

        public UserStore(ISession context)
            : base(new IdentityErrorDescriber())
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            this.ShouldDisposeSession = true;
            this.Context = context;
        }

        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            //return Task.FromResult(this.Context.Get<TUser>((object)userId));
            return this.GetUserAggregateAsync(u => u.Id.Equals(userId));
        }

        public override Task<TUser> FindByNameAsync(string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            //return Task.FromResult<TUser>(Queryable.FirstOrDefault<TUser>(Queryable.Where<TUser>(this.Context.Query<TUser>(), (Expression<Func<TUser, bool>>)(u => u.UserName.ToUpper() == userName.ToUpper()))));
            return this.GetUserAggregateAsync(u => u.UserName.ToUpper() == userName.ToUpper());
        }

        protected override async Task<TUser> FindUserAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(userId))
            {
                throw new ArgumentException(nameof(userId));
            }

            return await this.Context.GetAsync<TUser>(userId, cancellationToken);
        }

        protected override async Task<IdentityUserLogin> FindUserLoginAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(userId))
                throw new ArgumentException(nameof(userId));
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentException(nameof(providerKey));

            var query = from u in this.Users
                        where u.Id == userId
                        from l in u.Logins
                        where l.LoginProvider == loginProvider && l.ProviderKey == providerKey
                        select l;

            return await query.SingleOrDefaultAsync(cancellationToken);
        }

        protected override async Task<IdentityUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentException(nameof(providerKey));

            var query = from u in this.Users
                        from l in u.Logins
                        where l.LoginProvider == loginProvider && l.ProviderKey == providerKey
                        select l;

            return await query.SingleOrDefaultAsync(cancellationToken);
        }

        public override Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            Context.Save(user);
            Context.Flush();

            return Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            this.Context.Delete(user);
            Context.Flush();

            return Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            this.Context.Update(user);
            Context.Flush();

            return Task.FromResult(IdentityResult.Success);
        }

        public override async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            user.Logins.Add(new IdentityUserLogin
            {
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider
            });

            await this.Context.SaveOrUpdateAsync(user, cancellationToken);
        }

        public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentException(nameof(providerKey));

            user = await this.Context.MergeAsync(user, cancellationToken);
            var login = user.Logins.SingleOrDefault(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);
            if (login != null)
            {
                user.Logins.Remove(login);
                await this.Context.FlushAsync(cancellationToken);
            }
        }

        //public virtual Task RemoveLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        //{
        //    cancellationToken.ThrowIfCancellationRequested();
        //    this.ThrowIfDisposed();
        //    if (user == null)
        //        throw new ArgumentNullException(nameof(user));
        //    if (login == null)
        //        throw new ArgumentNullException(nameof(login));

        //    var info = user.Logins.SingleOrDefault(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);
        //    if (info != null)
        //    {
        //        user.Logins.Remove(info);
        //        this.Context.Update(user);
        //    }

        //    return Task.FromResult(0);
        //}

        public override Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            IList<UserLoginInfo> result = user.Logins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, user.UserName)).ToList();
            return Task.FromResult(result);
        }

        public override Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            IList<Claim> result = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult(result);
        }

        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));
            user = await this.Context.MergeAsync(user, cancellationToken);
            foreach (var claim in claims)
            {
                user.Claims.Add(new IdentityUserClaim
                {
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value,
                    User = user,
                    UserId = user.Id
                });
            }
            await this.Context.FlushAsync(cancellationToken);
        }

        public override async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));
            if (newClaim == null)
                throw new ArgumentNullException(nameof(newClaim));

            user = await this.Context.MergeAsync(user, cancellationToken);
            var userClaims = user.Claims;
            var matchedClaims = userClaims.Where(uc => uc.UserId.Equals(user.Id) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).ToList();
            foreach (var matchedClaim in matchedClaims)
            {
                matchedClaim.ClaimValue = newClaim.Value;
                matchedClaim.ClaimType = newClaim.Type;
            }

            await this.Context.FlushAsync(cancellationToken);
        }

        public override async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claimsToRemove, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claimsToRemove == null)
                throw new ArgumentNullException(nameof(claimsToRemove));

            user = await this.Context.MergeAsync(user, cancellationToken);
            var toRemoveList = claimsToRemove.ToList();
            var removeSet = user.Claims.Where(c => toRemoveList.Any(r => r.Type == c.ClaimType && r.Value == c.ClaimValue)).ToList();
            removeSet.ForEach(c => user.Claims.Remove(c));
            await this.Context.FlushAsync(cancellationToken);
        }

        public override async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var query = from userClaim in Context.Query<IdentityUserClaim>()
                        join user in Users on userClaim.UserId equals user.Id
                        where userClaim.ClaimValue == claim.Value && userClaim.ClaimType == claim.Type
                        select user;

            return await query.ToListAsync(cancellationToken);
        }

        // ReSharper disable once OptionalParameterHierarchyMismatch
        protected override async Task<IdentityUserToken<string>> FindTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException(nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException(nameof(name));

            user = await this.Context.MergeAsync(user, cancellationToken);
            var token = user.Tokens.SingleOrDefault(t => t.Name == name && t.LoginProvider == loginProvider);
            return token;
        }

        protected override Task AddUserTokenAsync(IdentityUserToken<string> token)
        {
            UserTokens.Add(token);
            return Task.CompletedTask;
        }

        protected override Task RemoveUserTokenAsync(IdentityUserToken<string> token)
        {
            UserTokens.Remove(token);
            return Task.CompletedTask;
        }

        //public virtual Task AddClaimAsync(TUser user, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        //{
        //    cancellationToken.ThrowIfCancellationRequested();
        //    this.ThrowIfDisposed();
        //    if (user == null)
        //    {
        //        throw new ArgumentNullException(nameof(user));
        //    }
        //    if (claim == null)
        //    {
        //        throw new ArgumentNullException(nameof(claim));
        //    }

        //    user.Claims.Add(new IdentityUserClaim()
        //    {
        //        User = user,
        //        ClaimType = claim.Type,
        //        ClaimValue = claim.Value
        //    });

        //    return Task.FromResult(0);
        //}

        //public virtual Task RemoveClaimAsync(TUser user, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        //{
        //    cancellationToken.ThrowIfCancellationRequested();
        //    this.ThrowIfDisposed();
        //    if (user == null)
        //    {
        //        throw new ArgumentNullException(nameof(user));
        //    }
        //    if (claim == null)
        //    {
        //        throw new ArgumentNullException(nameof(claim));
        //    }

        //    foreach (var identityUserClaim in Enumerable.ToList(Enumerable.Where(user.Claims, uc =>
        //    {
        //        if (uc.ClaimValue == claim.Value)
        //        {
        //            return uc.ClaimType == claim.Type;
        //        }
        //        else
        //        {
        //            return false;
        //        }
        //    })))
        //    {
        //        user.Claims.Remove(identityUserClaim);
        //    }

        //    return Task.FromResult(0);
        //}

        public virtual Task AddToRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(normalizedRoleName));
            }
            var roleEntity = await FindRoleAsync(normalizedRoleName, cancellationToken);
            if (roleEntity == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, Resources.RoleNotFound, normalizedRoleName));
            }
            UserRoles.Add(CreateUserRole(user, roleEntity));
        }

        public virtual Task RemoveFromRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(role))
            {
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(role));
            }

            var identityUserRole = user.Roles.FirstOrDefault(r => r.Name.ToUpper() == role.ToUpper());
            if (identityUserRole != null)
            {
                user.Roles.Remove(identityUserRole);
            }

            return Task.FromResult(0);
        }

        public virtual Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            else
            {
                return Task.FromResult((IList<string>)user.Roles.Select(u => u.Name).ToList());
            }
        }

        public virtual Task<bool> IsInRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(role))
            {
                throw new ArgumentException(Resources.ValueCannotBeNullOrEmpty, nameof(role));
            }
            else
            {
                return Task.FromResult(Enumerable.Any(user.Roles, r => r.Name.ToUpper() == role.ToUpper()));
            }
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            if (string.IsNullOrEmpty(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            var role = await FindRoleAsync(normalizedRoleName, cancellationToken);

            if (role != null)
            {
                var query = from userrole in UserRoles
                            join user in Users on userrole.UserId equals user.Id
                            where userrole.RoleId.Equals(role.Id)
                            select user;

                return await query.ToListAsync(cancellationToken);
            }
            return new List<TUser>();

        }

        public override IQueryable<TUser> Users
        {
            get
            {
                this.ThrowIfDisposed();
                return this.Context.Query<TUser>();
            }
        }

        //Task<DateTimeOffset?> IUserLockoutStore<TUser>.GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        //{
        //    cancellationToken.ThrowIfCancellationRequested();
        //    this.ThrowIfDisposed();
        //    throw new NotImplementedException();
        //}

        //public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd, CancellationToken cancellationToken = default(CancellationToken))
        //{
        //    DateTime? nullable;
        //    cancellationToken.ThrowIfCancellationRequested();
        //    this.ThrowIfDisposed();
        //    if (user == null)
        //    {
        //        throw new ArgumentNullException(nameof(user));
        //    }
        //    if (lockoutEnd == DateTimeOffset.MinValue)
        //    {
        //        nullable = null;
        //    }
        //    else
        //    {
        //        nullable = new DateTime?(lockoutEnd.UtcDateTime);
        //    }
        //    user.LockoutEndDateUtc = nullable;
        //    return Task.FromResult(0);
        //}

        public override Task<TUser> FindByEmailAsync(string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            return this.GetUserAggregateAsync(u => u.Email.ToUpper() == email.ToUpper());
        }

        private Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
        {
            return Task.Run(() =>
            {
                // no cartesian product, batch call. Don't know if it's really needed: should we eager load or let lazy loading do its stuff?
                var query = this.Context.Query<TUser>().Where(filter);
                query.Fetch(p => p.Roles).ToFuture();
                query.Fetch(p => p.Claims).ToFuture();
                query.Fetch(p => p.Logins).ToFuture();
                return query.ToFuture().FirstOrDefault();
            });
        }
    }
}
