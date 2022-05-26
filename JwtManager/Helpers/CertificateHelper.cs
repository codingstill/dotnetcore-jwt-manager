using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace JwtManager.Helpers
{
    public static class CertificateHelper
    {
        private static readonly string[] itemsToRemove = { "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----" };

        public static string LoadFromFile(string path)
        {
            return RemoveHeaderFooterFromKey(System.IO.File.ReadAllText(path));
        }

        public static string RemoveHeaderFooterFromKey(string key)
        {
            string tmp = key;
            foreach (string item in itemsToRemove)
            {
                tmp = tmp.Replace(item, string.Empty);
            }
            return tmp.Trim();
        }

        public static string GetPublicKey(string certificate)
        {
            byte[] certificateKeyBytes = Convert.FromBase64String(certificate);
            X509Certificate2 cert = new X509Certificate2(certificateKeyBytes);
            RSA publicKey = cert.GetRSAPublicKey();

            if(publicKey == null)
            {
                throw new Exception("Could not retrieve public key from certificate");
            }

            return Encoding.Default.GetString(publicKey.ExportSubjectPublicKeyInfo());
        }
    }
}
