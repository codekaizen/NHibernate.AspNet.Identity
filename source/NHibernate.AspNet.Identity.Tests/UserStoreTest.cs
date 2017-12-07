using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Transactions;
using Microsoft.AspNetCore.Identity;B
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using NHibernate.AspNet.Identity.Tests.Models;
using NHibernate.Linq;
using NUnit.Framework;
using TestClass = NUnit.Framework.TestFixtureAttribute;
using TestInitialize = NUnit.Framework.SetUpAttribute;
using TestCleanup = NUnit.Framework.TearDownAttribute;
using TestMethod = NUnit.Framework.TestAttribute;

namespace NHibernate.AspNet.Identity.Tests
{
    [TestClass]
    public class UserStoreTest
    {
        private ISession _session;
        private UserManager<ApplicationUser> _userManager;

        [TestInitialize]
        public void Initialize()
        {
            var factory = SessionFactoryProvider.Instance.SessionFactory;
            _session = factory.OpenSession();
            SessionFactoryProvider.Instance.BuildSchema();
            var serviceProviderMock = new Mock<IServiceProvider>();
            
            _userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(_session),
                new OptionsManager<IdentityOptions>(new OptionsFactory<IdentityOptions>(new IConfigureOptions<IdentityOptions>[0], new IPostConfigureOptions<IdentityOptions>[0])),
                new PasswordHasher<ApplicationUser>(new OptionsManager<PasswordHasherOptions>(new OptionsFactory<PasswordHasherOptions>(new IConfigureOptions<PasswordHasherOptions>[0], new IPostConfigureOptions<PasswordHasherOptions>[0]))),
                new IUserValidator<ApplicationUser>[0],
                new IPasswordValidator<ApplicationUser>[0],
                new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(),
                serviceProviderMock.Object,
                new Logger<UserManager<ApplicationUser>>(new LoggerFactory()));
        }

        [TestCleanup]
        public void Cleanup()
        {
            _session.Close();
        }

        [TestMethod]
        public async Task WhenHaveNoUser()
        {
            var store = new UserStore<IdentityUser>(_session);
            var user = await store.FindByLoginAsync("ProviderTest", "ProviderKey");

            Assert.IsNull(user);
        }

        [TestMethod]
        public async Task WhenAddLoginAsync()
        {
            var user = new IdentityUser("Lukz");
            var login = new UserLoginInfo("ProviderTest02", "ProviderKey02", "ProviderTest02");
            var store = new UserStore<IdentityUser>(_session);
            using (var ts = new TransactionScope(TransactionScopeOption.RequiresNew))
            {
                var result = store.AddLoginAsync(user, login);
                ts.Complete();
                Assert.IsNull(result.Exception);
            }

            var actual = _session.Query<IdentityUser>().FirstOrDefault(x => x.UserName == user.UserName);
            var userStored = await store.FindByLoginAsync(login.LoginProvider, login.ProviderKey);

            Assert.IsNotNull(actual);
            Assert.AreEqual(user.UserName, actual.UserName);
            Assert.AreEqual(user.UserName, userStored.UserName);
        }

        [TestMethod]
        public async Task WhenRemoveLoginAsync()
        {
            var user = new IdentityUser("Lukz 03");
            var login = new UserLoginInfo("ProviderTest03", "ProviderKey03", "ProviderTest03");
            var store = new UserStore<IdentityUser>(_session);
            await store.AddLoginAsync(user, login);

            Assert.IsTrue(user.Logins.Any());

            using (var ts = new TransactionScope(TransactionScopeOption.RequiresNew))
            {
                var result = store.RemoveLoginAsync(user, login.LoginProvider, login.ProviderKey);
                ts.Complete();
                Assert.IsNull(result.Exception);
            }

            var actual = _session.Query<IdentityUser>().FirstOrDefault(x => x.UserName == user.UserName);
            Assert.IsFalse(actual.Logins.Any());
        }

        [TestMethod]
        public void WhenCreateUserAsync()
        {
            var user = new ApplicationUser() { UserName = "RealUserName" };

            using (var transaction = new TransactionScope())
            {
                var result = userManager.CreateAsync(user, "RealPassword").GetAwaiter().GetResult();
                transaction.Complete();
                Assert.AreEqual(0, result.Errors.Count());
            }

            var actual = _session.Query<ApplicationUser>().FirstOrDefault(x => x.UserName == user.UserName);

            Assert.IsNotNull(actual);
            Assert.AreEqual(user.UserName, actual.UserName);
        }

        [TestMethod]
        public void GivenHaveRoles_WhenDeleteUser_ThenDeletingCausesNoCascade()
        {
            var user = new IdentityUser("Lukz 04");
            var role = new IdentityRole("ADM");
            var store = new UserStore<IdentityUser>(_session);
            var roleStore = new RoleStore<IdentityRole>(_session);

            roleStore.CreateAsync(role);
            store.CreateAsync(user);
            store.AddToRoleAsync(user, "ADM");

            Assert.IsTrue(_session.Query<IdentityRole>().Any(x => x.Name == "ADM"));
            Assert.IsTrue(_session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 04"));

            var result = store.DeleteAsync(user);

            Assert.IsNull(result.Exception);
            Assert.IsFalse(this._session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 04"));
            Assert.IsTrue(this._session.Query<IdentityRole>().Any(x => x.Name == "ADM"));
        }

        [TestMethod]
        public async Task WhenRemoveUserFromRole_ThenDoNotDeleteRole_BugFix()
        {
            var user = new IdentityUser("Lukz 05");
            var role = new IdentityRole("ADM05");
            var store = new UserStore<IdentityUser>(_session);
            var roleStore = new RoleStore<IdentityRole>(_session);

            roleStore.CreateAsync(role);
            store.CreateAsync(user);
            store.AddToRoleAsync(user, "ADM05");

            Assert.IsTrue(_session.Query<IdentityRole>().Any(x => x.Name == "ADM05"));
            Assert.IsTrue(_session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 05"));
            Assert.IsTrue(await store.IsInRoleAsync(user, "ADM05"));

            var result = store.RemoveFromRoleAsync(user, "ADM05");

            Assert.IsNull(result.Exception);
            Assert.IsFalse(await store.IsInRoleAsync(user, "ADM05"));
            Assert.IsTrue(_session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 05"));
            Assert.IsTrue(_session.Query<IdentityRole>().Any(x => x.Name == "ADM05"));
        }

        [TestMethod]
        public async Task GetAllUsers()
        {
            var user1 = new IdentityUser("Lukz 04");
            var user2 = new IdentityUser("Moa 01");
            var user3 = new IdentityUser("Win 02");
            var user4 = new IdentityUser("Andre 03");
            var role = new IdentityRole("ADM");
            var store = new UserStore<IdentityUser>(this._session);
            var roleStore = new RoleStore<IdentityRole>(this._session);

            await roleStore.CreateAsync(role);
            await store.CreateAsync(user1);
            await store.CreateAsync(user2);
            await store.CreateAsync(user3);
            await store.CreateAsync(user4);
            await store.AddToRoleAsync(user1, "ADM");
            await store.AddToRoleAsync(user2, "ADM");
            await store.AddToRoleAsync(user3, "ADM");
            await store.AddToRoleAsync(user4, "ADM");

            Assert.IsTrue(this._session.Query<IdentityRole>().Any(x => x.Name == "ADM"));
            Assert.IsTrue(this._session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 04"));

            Assert.IsTrue(this._session.Query<IdentityUser>().Any(x => x.UserName == "Andre 03"));

            var resul = store.Users;

            Assert.AreEqual(4, resul.Count());
        }

        [TestMethod]
        public async Task GetAllRoles()
        {
            var user1 = new IdentityUser("Lukz 04");
            var user2 = new IdentityUser("Moa 01");
            var user3 = new IdentityUser("Win 02");
            var user4 = new IdentityUser("Andre 03");
            var role = new IdentityRole("ADM");
            var role2 = new IdentityRole("USR");
            var store = new UserStore<IdentityUser>(this._session);
            var roleStore = new RoleStore<IdentityRole>(this._session);

            await roleStore.CreateAsync(role);
            await roleStore.CreateAsync(role2);
            await store.CreateAsync(user1);
            await store.CreateAsync(user2);
            await store.CreateAsync(user3);
            await store.CreateAsync(user4);
            await store.AddToRoleAsync(user1, "ADM");
            await store.AddToRoleAsync(user2, "ADM");
            await store.AddToRoleAsync(user3, "ADM");
            await store.AddToRoleAsync(user4, "ADM");
            await store.AddToRoleAsync(user1, "USR");
            await store.AddToRoleAsync(user4, "USR");

            Assert.IsTrue(this._session.Query<IdentityRole>().Any(x => x.Name == "ADM"));
            Assert.IsTrue(this._session.Query<IdentityUser>().Any(x => x.UserName == "Lukz 04"));

            Assert.IsTrue(this._session.Query<IdentityUser>().Any(x => x.UserName == "Andre 03"));

            var result = roleStore.Roles;

            Assert.AreEqual(2, result.Count());
        }

        [TestMethod]
        public async Task LockoutAccount()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            userManager.MaxFailedAccessAttemptsBeforeLockout = 3;
            userManager.UserLockoutEnabledByDefault = true;
            userManager.DefaultAccountLockoutTimeSpan = new TimeSpan(0, 10, 0);
            userManager.Create(new ApplicationUser() { UserName = "test", LockoutEnabled = true }, "Welcome");
            var user = userManager.Find("test", "Welcome");
            Assert.AreEqual(0, userManager.GetAccessFailedCount(user.Id));
            userManager.AccessFailed(user.Id);
            Assert.AreEqual(1, userManager.GetAccessFailedCount(user.Id));
            userManager.AccessFailed(user.Id);
            Assert.AreEqual(2, userManager.GetAccessFailedCount(user.Id));
            userManager.AccessFailed(user.Id);
            Assert.IsTrue(userManager.IsLockedOut(user.Id));
        }

        [TestMethod]
        public async Task FindByName()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            userManager.Create(new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome");
            var x = userManager.FindByName("tEsT");
            Assert.IsNotNull(x);
            Assert.IsTrue(userManager.IsEmailConfirmed(x.Id));
        }

        [TestMethod]
        public async Task FindByNameWithRoles()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(this._session));
            roleManager.Create(new IdentityRole("Admin"));
            roleManager.Create(new IdentityRole("AO"));
            var user = new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true };
            userManager.Create(user, "Welcome");
            userManager.AddToRole(user.Id, "Admin");
            userManager.AddToRole(user.Id, "AO");
            // clear session
            this._session.Flush();
            this._session.Clear();

            var x = userManager.FindByName("tEsT");
            Assert.IsNotNull(x);
            Assert.AreEqual(2, x.Roles.Count);
        }

        [TestMethod]
        public async Task FindByEmail()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            userManager.Create(new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome");
            var x = userManager.FindByEmail("AaA@bBb.com");
            Assert.IsNotNull(x);
            Assert.IsTrue(userManager.IsEmailConfirmed(x.Id));
        }

        [TestMethod]
        public async Task AddClaim()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            var user = new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true };
            userManager.Create(user, "Welcome");
            userManager.AddClaim(user.Id, new Claim(ClaimTypes.Role, "Admin"));
            Assert.AreEqual(1, userManager.GetClaims(user.Id).Count());
        }

        [TestMethod]
        public async Task EmailConfirmationToken()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            userManager.UserTokenProvider = new EmailTokenProvider<ApplicationUser, string>() { BodyFormat = "xxxx {0}", Subject = "Reset password" };
            userManager.Create(new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = false }, "Welcome");
            var x = userManager.FindByEmail("aaa@bbb.com");
            string token = userManager.GeneratePasswordResetToken(x.Id);
            userManager.ResetPassword(x.Id, token, "Welcome!");
        }

        [TestMethod]
        public async Task FindByEmailAggregated()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(this._session));
            userManager.Create(new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome");
            var x = userManager.FindByEmail("aaa@bbb.com");
            roleManager.CreateAsync(new IdentityRole("Admin"));
            userManager.AddClaim(x.Id, new Claim("role", "admin"));
            userManager.AddClaim(x.Id, new Claim("role", "user"));
            userManager.AddToRole(x.Id, "Admin");
            userManager.AddLogin(x.Id, new UserLoginInfo("facebook", "1234"));
            this._session.Clear();
            x = userManager.FindByEmail("aaa@bbb.com");
            Assert.IsNotNull(x);
            Assert.AreEqual(2, x.Claims.Count);
            Assert.AreEqual(1, x.Roles.Count);
            Assert.AreEqual(1, x.Logins.Count);
        }

        [TestMethod]
        public async Task CreateWithoutCommitingTransactionScopeShouldNotInsertRows()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(this._session));
            using (var ts = new TransactionScope(TransactionScopeOption.RequiresNew))
            {
                // session is not opened inside the scope so we need to enlist it manually
                ((System.Data.Common.DbConnection)_session.Connection).EnlistTransaction(System.Transactions.Transaction.Current);
                userManager.Create(new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome1");
                var x = userManager.FindByEmail("aaa@bbb.com");
                roleManager.Create(new IdentityRole("Admin"));
                userManager.AddClaim(x.Id, new Claim("role", "admin"));
                userManager.AddClaim(x.Id, new Claim("role", "user"));
                userManager.AddToRole(x.Id, "Admin");
                userManager.AddLogin(x.Id, new UserLoginInfo("facebook", "1234"));
            }
            var x2 = userManager.FindByEmail("aaa@bbb.com");
            Assert.IsNull(x2);
        }

        [TestMethod]
        public async Task CreateWithoutCommitingNHibernateTransactionShouldNotInsertRows()
        {
            var userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(this._session));
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(this._session));
            using (var ts = _session.BeginTransaction())
            {
                userManager.Create(new ApplicationUser() { UserName = "test", Email = "aaa@bbb.com", EmailConfirmed = true }, "Welcome1");
                var x = userManager.FindByEmail("aaa@bbb.com");
                roleManager.Create(new IdentityRole("Admin"));
                userManager.AddClaim(x.Id, new Claim("role", "admin"));
                userManager.AddClaim(x.Id, new Claim("role", "user"));
                userManager.AddToRole(x.Id, "Admin");
                userManager.AddLogin(x.Id, new UserLoginInfo("facebook", "1234"));
            }
            var x2 = userManager.FindByEmail("aaa@bbb.com");
            Assert.IsNull(x2);
        }
    }
}
