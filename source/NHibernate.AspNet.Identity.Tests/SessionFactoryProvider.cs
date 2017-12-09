using System;
using System.IO;
using System.Linq;
using NHibernate.AspNet.Identity.DomainModel;
using NHibernate.AspNet.Identity.Tests.Models;
using NHibernate.Cfg;
using NHibernate.Cfg.MappingSchema;
using NHibernate.Mapping.ByCode;
using NHibernate.Tool.hbm2ddl;

namespace NHibernate.AspNet.Identity.Tests
{
    public sealed class SessionFactoryProvider
    {
        private static volatile SessionFactoryProvider _instance;
        private static object _syncRoot = new Object();
        private Configuration _configuration;

        public ISessionFactory SessionFactory { get; }
        public string Name { get; }

        /// <summary>
        /// constructor configures a SessionFactory based on the configuration passed in
        /// </summary>
        private SessionFactoryProvider()
        {
            Name = "NHibernate.AspNet.Identity";

            var allEntities = new[] { 
                typeof(IdentityUser), 
                typeof(ApplicationUser), 
                typeof(IdentityRole), 
                typeof(IdentityUserClaim),
                typeof(IdentityUserToken),
                typeof(IdentityUserLogin),
            };

            var mapper = new ModelMapper();
            //DefineBaseClass(mapper, baseEntityToIgnore);
            //mapper.IsComponent((type, declared) => typeof(ValueObject).IsAssignableFrom(type));

            mapper.AddMapping<ApplicationUserMap>();
            mapper.AddMapping<IdentityUserMap>();
            mapper.AddMapping<IdentityRoleMap>();
            mapper.AddMapping<IdentityUserClaimMap>();
            mapper.AddMapping<IdentityUserTokenMap>();
            //mapper.AddMapping<IdentityUserLoginMap>();

            //var mapping = mapper.CompileMappingForEach(allEntities);

            _configuration = new Configuration();
            _configuration.Configure("sqlite-nhibernate-config.xml");
            //foreach (var map in mapping)
            //{
            //    Console.WriteLine(map.AsString());
            //    _configuration.AddDeserializedMapping(map, null);
            //}
            _configuration.AddXml(_hbm);
            _configuration.AddXml(_testHbm);
            SessionFactory = _configuration.BuildSessionFactory();
        }

        private readonly string _hbm = @"<?xml version=""1.0"" encoding=""utf-8""?>
<hibernate-mapping xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" namespace=""NHibernate.AspNet.Identity"" assembly=""NHibernate.AspNet.Identity, Version=5.0.2.0, Culture=neutral, PublicKeyToken=null"" xmlns=""urn:nhibernate-mapping-2.2"">
  <class name=""IdentityUser"" table=""AspNetUsers"">
    <id name=""Id"" type=""String"">
      <generator class=""uuid.hex"">
        <param name=""format"">D</param>
      </generator>
    </id>
    <property name=""LockoutEndDateUtc"" />
    <bag name=""Roles"" table=""AspNetUserRoles"">
      <key column=""UserId"" />
      <many-to-many class=""IdentityRole"" column=""RoleId"" />
    </bag>
    <bag name=""Claims"" cascade=""all,delete-orphan"">
      <key column=""UserId"" update=""false"" />
      <one-to-many class=""IdentityUserClaim"" />
    </bag>
    <set name=""Logins"" table=""AspNetUserLogins"" cascade=""all,delete-orphan"">
      <key column=""UserId"" />
      <one-to-many class=""IdentityUserLogin"" />
    </set>
    <bag name=""Tokens"" table=""AspNetUserTokens"">
      <key column=""UserId"" />
      <one-to-many class=""IdentityUserToken"" />
    </bag>
    <property name=""UserName"" length=""255"" not-null=""true"" unique=""true"" />
    <property name=""Email"" />
    <property name=""EmailConfirmed"" />
    <property name=""PasswordHash"" />
    <property name=""SecurityStamp"" />
    <property name=""PhoneNumber"" />
    <property name=""PhoneNumberConfirmed"" />
    <property name=""TwoFactorEnabled"" />
    <property name=""LockoutEnabled"" />
    <property name=""AccessFailedCount"" />
  </class>  

  <class name=""IdentityRole"" table=""AspNetRoles"">
    <id name=""Id"" type=""String"">
      <generator class=""uuid.hex"">
        <param name=""format"">D</param>
      </generator>
    </id>
    <property name=""Name"" length=""255"" not-null=""true"" unique=""true"" />
    <property name=""NormalizedName"" length=""255"" not-null=""true"" unique=""true"" />
    <bag name=""Users"" table=""AspNetUserRoles"">
      <key column=""RoleId"" />
      <many-to-many class=""IdentityUser"" column=""UserId"" />
    </bag>
  </class>  

  <class name=""IdentityUserClaim"" table=""AspNetUserClaims"">
    <id name=""Id"" type=""Int32"">
        <generator class=""hilo"">
            <param name=""table"">KeyPool</param>
            <param name=""column"">NextHigh</param>
            <param name=""max_lo"">100</param>
        </generator>
    </id>
    <property name=""ClaimType"" />
    <property name=""ClaimValue"" />
    <many-to-one name=""User"" column=""UserId"" />
  </class>  

  <class name=""IdentityUserToken"" table=""AspNetUserTokens"">
    <composite-id>
      <key-property name=""UserId"" />
      <key-property name=""LoginProvider"" />
      <key-property name=""Name"" />
    </composite-id>
    <property name=""Value"" length=""65535"" not-null=""true"" />
  </class>

  <class name=""IdentityUserLogin"" table=""AspNetUserLogins"">
    <composite-id>
      <key-property name=""LoginProvider"" />
      <key-property name=""ProviderKey"" />
    </composite-id>
    <property name=""ProviderDisplayName"" length=""256"" not-null=""true"" />
  </class>
</hibernate-mapping>
";

        private readonly string _testHbm = @"<?xml version=""1.0"" encoding=""utf-8""?>
<hibernate-mapping xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"" namespace=""NHibernate.AspNet.Identity.Tests.Models"" assembly=""NHibernate.AspNet.Identity.Tests, Version=5.0.2.0, Culture=neutral, PublicKeyToken=null"" xmlns=""urn:nhibernate-mapping-2.2"">
  <class name=""ApplicationUser"" table=""AspNetUsers"">
    <id name=""Id"" type=""String"">
      <generator class=""uuid.hex"">
        <param name=""format"">D</param>
      </generator>
    </id>
    <property name=""AccessFailedCount"" />
    <property name=""Email"" />
    <property name=""EmailConfirmed"" />
    <property name=""LockoutEnabled"" />
    <property name=""LockoutEndDateUtc"" />
    <property name=""PasswordHash"" />
    <property name=""PhoneNumber"" />
    <property name=""PhoneNumberConfirmed"" />
    <property name=""TwoFactorEnabled"" />
    <property name=""UserName"" length=""255"" not-null=""true"" unique=""true"" />
    <property name=""SecurityStamp"" />
    <bag name=""Claims"" cascade=""all,delete-orphan"">
      <key column=""UserId"" update=""false"" />
      <one-to-many class=""NHibernate.AspNet.Identity.IdentityUserClaim, NHibernate.AspNet.Identity, Version=5.0.2.0, Culture=neutral, PublicKeyToken=null"" />
    </bag>
    <set name=""Logins"" table=""AspNetUserLogins"" cascade=""all,delete-orphan"">
      <key column=""UserId"" />
      <one-to-many class=""NHibernate.AspNet.Identity.IdentityUserLogin, NHibernate.AspNet.Identity, Version=5.0.2.0, Culture=neutral, PublicKeyToken=null"" />
    </set>
    <bag name=""Roles"" table=""AspNetUserRoles"">
      <key column=""UserId"" />
      <many-to-many class=""NHibernate.AspNet.Identity.IdentityRole, NHibernate.AspNet.Identity, Version=5.0.2.0, Culture=neutral, PublicKeyToken=null"" column=""RoleId"" />
    </bag>
    <bag name=""Tokens"" table=""AspNetUserTokens"">
      <key column=""UserId"" />
      <one-to-many class=""NHibernate.AspNet.Identity.IdentityUserToken, NHibernate.AspNet.Identity, Version=5.0.2.0, Culture=neutral, PublicKeyToken=null"" />
    </bag>
  </class>
</hibernate-mapping>";

        public static SessionFactoryProvider Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (_syncRoot)
                    {
                        if (_instance == null)
                            _instance = new SessionFactoryProvider();
                    }
                }
                return _instance;
            }
        }

        public void BuildSchema()
        {
            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"schema.sql");

            // this NHibernate tool takes a configuration (with mapping info in)
            // and exports a database schema from it
            new SchemaExport(_configuration)
                .SetOutputFile(path)
                .Create(true, true /* DROP AND CREATE SCHEMA */);
        }

        //private static void DefineBaseClass(ConventionModelMapper mapper, System.Type[] baseEntityToIgnore)
        //{
        //    if (baseEntityToIgnore == null)
        //        return;
        //    mapper.IsEntity((type, declared) =>
        //        baseEntityToIgnore.Any(x => x.IsAssignableFrom(type)) &&
        //        baseEntityToIgnore.All(x => x != type) &&
        //        !type.IsInterface);
        //    mapper.IsRootEntity((type, declared) => baseEntityToIgnore.Any(x => x == type.BaseType));
        //}

    }
}
