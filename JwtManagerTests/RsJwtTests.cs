using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JwtManagerTests
{
    [TestClass]
    public abstract class RsJwtTests
    {
        #region Private Members
        private static string PrivateKey = string.Empty;
        private static string PublicKey = string.Empty;

        private static string KeySize = string.Empty;
        private static string OpenSslBinPath = string.Empty;

        private static string CurrentPath = string.Empty;
        #endregion

        #region Setup Methods
        [ClassInitialize]
        public static void BaseClassInitialize(TestContext context)
        {
            AppSettingsSection AppSettings = ConfigurationManager.OpenExeConfiguration(Assembly.GetExecutingAssembly().Location).AppSettings;

            KeySize = AppSettings.Settings["KeySize"].Value;
            OpenSslBinPath = AppSettings.Settings["OpenSslBinPath"].Value;

            CurrentPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string commands = string.Format(@"{0}openssl genrsa -out private{1}.key {1}
{0}openssl rsa -in private{1}.key -outform PEM -pubout -out public{1}.pem", OpenSslBinPath, KeySize);

            File.WriteAllText(string.Format("{0}\\create.bat", CurrentPath), commands);

            ProcessStartInfo proc = new ProcessStartInfo
            {
                Arguments = @"/c create.bat",
                CreateNoWindow = true,
                FileName = @"C:\windows\system32\cmd.exe",
                RedirectStandardOutput = true,
                WorkingDirectory = CurrentPath,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            Process cmd = Process.Start(proc);
            string output = cmd.StandardOutput.ReadToEnd();
            cmd.WaitForExit();

            PrivateKey = JwtManager.Helpers.KeyHelper.LoadFromFile(string.Format("{0}\\private{1}.key", CurrentPath, KeySize));
            PublicKey = JwtManager.Helpers.KeyHelper.LoadFromFile(string.Format("{0}\\public{1}.pem", CurrentPath, KeySize));
        }

        [TestInitialize]
        public void BaseTestInitialize() { }

        [TestCleanup]
        public void BaseTestCleanup() { }

        [ClassCleanup]
        public static void BaseClassCleanup()
        {
            File.Delete(string.Format("{0}\\private{1}.key", CurrentPath, KeySize));
            File.Delete(string.Format("{0}\\public{1}.pem", CurrentPath, KeySize));
            File.Delete(string.Format("{0}\\create.bat", CurrentPath));
        }
        #endregion

        [TestMethod]
        public void InitClass()
        {
            JwtManager.RsJwt jwt = new JwtManager.RsJwt();

            Assert.IsTrue(jwt != null, "Object should not be null");
        }

        [TestMethod]
        public void SignData()
        {
            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PrivateKey = PrivateKey
            };

            string data = "{a:1,b:2}";
            string signedData = jwt.Sign(data);

            Assert.IsTrue(signedData != null, "Object should not be null");
        }

        [TestMethod]
        public void ValidateData()
        {
            string data = "{a:1,b:2}";
            JwtManager.RsJwt signJwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PrivateKey = PrivateKey
            };
            string signedData = signJwt.Sign(data);

            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PublicKey = PublicKey
            };
            string validatedData = jwt.Validate(signedData);

            Assert.AreEqual(data, validatedData, "Signed data should match the original data");
        }

        [TestMethod]
        public void ValidateInvalidData()
        {
            Exception e = null;
            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PublicKey = PublicKey
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
        public void SignInvalidPrivateKey()
        {
            Exception e = null;
            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PrivateKey = PrivateKey + "a"
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
        }

        [TestMethod]
        public void ValidateInvalidPublicKey()
        {
            Exception e = null;
            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PublicKey = PublicKey + "a"
            };

            try
            {
                string data = "{a:1,b:2}";
                string signedData = jwt.Sign(data);
                string validatedData = jwt.Validate(signedData);
            }
            catch (Exception ex)
            {
                e = ex;
            }

            Assert.IsNotNull(e, "An exception should be thrown");
        }

        [TestMethod]
        public void ValidateOtherPublicKey1()
        {
            Exception e = null;
            JwtManager.RsJwt sJwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PrivateKey = PrivateKey
            };
            JwtManager.RsJwt vJwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PrivateKey = PrivateKey
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
        }

        [TestMethod]
        public void ValidateOtherPublicKey2()
        {
            Exception e = null;
            JwtManager.RsJwt sJwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PublicKey = PublicKey
            };

            try
            {
                string data = "{a:1,b:2}";
                string signedData = sJwt.Sign(data);
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
            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
                KeySize = (JwtManager.Enums.KeySize)555,
                PrivateKey = PrivateKey
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
            Assert.AreEqual(e.Message, "Invalid values for algorithm or size.");
        }

        [TestMethod]
        public void ValidateWithInvalidHashAlgorithm()
        {
            Exception e = null;
            JwtManager.RsJwt sJwt = new JwtManager.RsJwt
            {
                KeySize = HashKeySize(),
                PrivateKey = PrivateKey
            };
            JwtManager.RsJwt vJwt = new JwtManager.RsJwt
            {
                KeySize = (JwtManager.Enums.KeySize)555,
                PublicKey = PublicKey
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
            Assert.AreEqual(e.Message, "Given key size is not valid.");
        }

        protected abstract JwtManager.Enums.KeySize HashKeySize();
    }

    [TestClass]
    public class Rs256Tests : RsJwtTests
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

        protected override JwtManager.Enums.KeySize HashKeySize()
        {
            return JwtManager.Enums.KeySize.S256;
        }
    }

    [TestClass]
    public class Rs384Tests : RsJwtTests
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

        protected override JwtManager.Enums.KeySize HashKeySize()
        {
            return JwtManager.Enums.KeySize.S384;
        }
    }

    [TestClass]
    public class Rs512Tests : RsJwtTests
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

        protected override JwtManager.Enums.KeySize HashKeySize()
        {
            return JwtManager.Enums.KeySize.S512;
        }
    }
}
