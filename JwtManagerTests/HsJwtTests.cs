using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JwtManagerTests
{
    [TestClass]
    public abstract class HsJwtTests
    {
        #region Private Members
        private static string Secret = string.Empty;
        #endregion

        #region Setup Methods
        [ClassInitialize]
        public static void BaseClassInitialize(TestContext context)
        {
            AppSettingsSection AppSettings = ConfigurationManager.OpenExeConfiguration(Assembly.GetExecutingAssembly().Location).AppSettings;

            Secret = "secret";
        }

        [TestInitialize]
        public void BaseTestInitialize() { }

        [TestCleanup]
        public void BaseTestCleanup() { }

        [ClassCleanup]
        public static void BaseClassCleanup()
        {
        }
        #endregion

        [TestMethod]
        public void InitClass()
        {
            JwtManager.HsJwt jwt = new JwtManager.HsJwt();

            Assert.IsTrue(jwt != null, "Object should not be null");
        }

        [TestMethod]
        public void SignData()
        {
            JwtManager.HsJwt jwt = new JwtManager.HsJwt
            {
                KeySize = HashKeySize(),
                Secret = Secret
            };

            string data = "{a:1,b:2}";
            string signedData = jwt.Sign(data);

            Assert.IsTrue(signedData != null, "Object should not be null");
        }

        [TestMethod]
        public void ValidateData()
        {
            string data = "{a:1,b:2}";
            JwtManager.HsJwt signJwt = new JwtManager.HsJwt
            {
                KeySize = HashKeySize(),
                Secret = Secret
            };

            string signedData = signJwt.Sign(data); //"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjoxLCJiIjoyfQ.oUNhDI_ELestyvPnldXA0UR_FycJW8TXLQqJmr9mSY0";

            JwtManager.HsJwt jwt = new JwtManager.HsJwt
            {
                KeySize = HashKeySize(),
                Secret = Secret
            };
            string validatedData = jwt.Validate(signedData);

            Assert.AreEqual(data, validatedData, "Object should not be null");
        }

        [TestMethod]
        public void ValidateInvalidData()
        {
            Exception e = null;
            JwtManager.HsJwt jwt = new JwtManager.HsJwt
            {
                KeySize = HashKeySize(),
                Secret = Secret
            };

            try
            {
                string data = "{a:1,b:2}";
                string signedData = jwt.Sign(data);
                string validatedData = jwt.Validate(signedData + "a");
            }
            catch (Exception ex)
            {
                e = ex;
            }


            Assert.IsNotNull(e, "An exception should be thrown");
        }

        [TestMethod]
        public void SignDataWithInvalidHashAlgorithm()
        {
            Exception e = null;
            JwtManager.HsJwt jwt = new JwtManager.HsJwt
            {
                KeySize = 555,
                Secret = Secret
            };

            try
            {
                string data = "{a:1,b:2}";
                string signedData = jwt.Sign(data);
            }
            catch (Exception ex)
            {
                e = ex;
            }


            Assert.IsNotNull(e, "An exception should be thrown");
            Assert.AreEqual(e.Message, "Non-valid key size.");
        }

        [TestMethod]
        public void ValidateWithInvalidHashAlgorithm()
        {
            Exception e = null;
            JwtManager.HsJwt sJwt = new JwtManager.HsJwt
            {
                KeySize = HashKeySize(),
                Secret = Secret
            };
            JwtManager.HsJwt vJwt = new JwtManager.HsJwt
            {
                KeySize = 555,
                Secret = Secret
            };

            try
            {
                string data = "{a:1,b:2}";
                string signedData = sJwt.Sign(data);
                Assert.IsNull(e, "An exception should not be thrown here");
                string validatedData = vJwt.Validate(signedData);
            }
            catch (Exception ex)
            {
                e = ex;
            }

            Assert.IsNotNull(e, "An exception should be thrown");
            Assert.AreEqual(e.Message, "Non-valid key size.");
        }

        [TestMethod]
        public void ValidateWithInvalidSecret()
        {
            Exception e = null;
            JwtManager.HsJwt sJwt = new JwtManager.HsJwt
            {
                KeySize = HashKeySize(),
                Secret = Secret
            };
            JwtManager.HsJwt vJwt = new JwtManager.HsJwt
            {
                KeySize = HashKeySize(),
                Secret = Secret + "a"
            };

            try
            {
                string data = "{a:1,b:2}";
                string signedData = sJwt.Sign(data);
                Assert.IsNull(e, "An exception should not be thrown here");
                string validatedData = vJwt.Validate(signedData);
            }
            catch (Exception ex)
            {
                e = ex;
            }

            Assert.IsNotNull(e, "An exception should be thrown");
            Assert.AreEqual(e.Message, "Invalid signature.");
        }

        protected abstract int HashKeySize();
    }

    [TestClass]
    public class Hs256Tests : HsJwtTests
    {
        #region Setup Methods
        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            BaseClassInitialize(context);
        }

        [TestInitialize]
        public void Initialize()
        {
            BaseTestInitialize();
        }

        [TestCleanup]
        public void Cleanup()
        {
            BaseTestCleanup();
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            BaseClassCleanup();
        }
        #endregion

        protected override int HashKeySize()
        {
            return 256;
        }
    }

    [TestClass]
    public class Hs384Tests : HsJwtTests
    {
        #region Setup Methods
        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            BaseClassInitialize(context);
        }

        [TestInitialize]
        public void Initialize()
        {
            BaseTestInitialize();
        }

        [TestCleanup]
        public void Cleanup()
        {
            BaseTestCleanup();
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            BaseClassCleanup();
        }
        #endregion

        protected override int HashKeySize()
        {
            return 256;
        }
    }

    [TestClass]
    public class Hs512Tests : HsJwtTests
    {
        #region Setup Methods
        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            BaseClassInitialize(context);
        }

        [TestInitialize]
        public void Initialize()
        {
            BaseTestInitialize();
        }

        [TestCleanup]
        public void Cleanup()
        {
            BaseTestCleanup();
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            BaseClassCleanup();
        }
        #endregion

        protected override int HashKeySize()
        {
            return 256;
        }
    }

}
