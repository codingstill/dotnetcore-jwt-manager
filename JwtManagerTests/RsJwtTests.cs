using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JwtManagerTests
{
    [TestClass]
    public class RsJwtTests
    {
        #region Keys
        private static string PrivateKey = string.Empty;
        private static string PublicKey = string.Empty;
        private static string KeySize = string.Empty;
        private static string CurrentPath = string.Empty;
        #endregion

        #region Setup Methods
        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            KeySize = ConfigurationManager.OpenExeConfiguration(Assembly.GetExecutingAssembly().Location).AppSettings.Settings["KeySize"].Value;

            CurrentPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string commands = string.Format(@"C:\OpenSSL-Win32\bin\openssl genrsa -out private{0}.key {0}
C:\OpenSSL-Win32\bin\openssl rsa -in private{0}.key -outform PEM -pubout -out public{0}.pem", KeySize);

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
        public void Initialize() { }

        [TestCleanup]
        public void Cleanup() { }

        [ClassCleanup]
        public static void ClassCleanup()
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
                PrivateKey = PrivateKey
            };
            string signedData = signJwt.Sign(data);

            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
                PrivateKey = PrivateKey,
                PublicKey = PublicKey
            };
            string validatedData = jwt.Validate(signedData);

            Assert.AreEqual(data, validatedData, "Object should not be null");
        }

        [TestMethod]
        public void ValidateInvalidData()
        {
            Exception e = null;
            JwtManager.RsJwt jwt = new JwtManager.RsJwt
            {
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
                PrivateKey = PrivateKey
            };
            JwtManager.RsJwt vJwt = new JwtManager.RsJwt
            {
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
    }
}
