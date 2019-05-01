using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace JwtManagerTests
{
    [TestClass]
    public class JwtHeaderTests
    {
        class TestResult
        {
            public JwtManager.Helpers.Algorithm algorithm { get; set; }
            public JwtManager.Helpers.KeySize size { get; set; }
            public string alg { get; set; }
            public string typ { get; set; }
        }

        [TestMethod]
        public void ValidCases()
        {
            JwtManager.JwtHeader header = new JwtManager.JwtHeader();

            TestResult[] tests = {
                new TestResult { algorithm = JwtManager.Helpers.Algorithm.RSA, size = JwtManager.Helpers.KeySize.S256, alg = "RS256", typ = "JWT" },
                new TestResult { algorithm = JwtManager.Helpers.Algorithm.RSA, size = JwtManager.Helpers.KeySize.S384, alg = "RS384", typ = "JWT" },
                new TestResult { algorithm = JwtManager.Helpers.Algorithm.RSA, size = JwtManager.Helpers.KeySize.S512, alg = "RS512", typ = "JWT" },
                new TestResult { algorithm = JwtManager.Helpers.Algorithm.HMAC, size = JwtManager.Helpers.KeySize.S256, alg = "HS256", typ = "JWT" },
                new TestResult { algorithm = JwtManager.Helpers.Algorithm.HMAC, size = JwtManager.Helpers.KeySize.S384, alg = "HS384", typ = "JWT" },
                new TestResult { algorithm = JwtManager.Helpers.Algorithm.HMAC, size = JwtManager.Helpers.KeySize.S512, alg = "HS512", typ = "JWT" }
            };

            foreach(TestResult test in tests)
            {
                header.Set(test.algorithm, test.size);
                Assert.AreEqual(header.alg, test.alg);
                Assert.AreEqual(header.typ, test.typ);
            }
        }

        [TestMethod]
        public void CheckEP512Exception()
        {
            JwtManager.JwtHeader header = new JwtManager.JwtHeader();
            Exception e = null;

            try
            {
                header.Set(JwtManager.Helpers.Algorithm.RSASSA, JwtManager.Helpers.KeySize.S512);
            }
            catch(Exception ex)
            {
                e = ex;
            }

            Assert.IsNotNull(e);
            Assert.AreEqual(e.Message, "Invalid size for algorithm.");
        }

        [TestMethod]
        public void CheckNonValidOptions()
        {
            JwtManager.JwtHeader header = new JwtManager.JwtHeader();
            Exception e = null;

            try
            {
                header.Set(JwtManager.Helpers.Algorithm.RSASSA, (JwtManager.Helpers.KeySize)555);
            }
            catch (Exception ex)
            {
                e = ex;
            }

            Assert.IsNotNull(e);
            Assert.AreEqual(e.Message, "Invalid values for algorithm or size.");
        }
    }
}
