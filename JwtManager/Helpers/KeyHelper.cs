using System;
using System.Collections.Generic;
using System.Text;

namespace JwtManager.Helpers
{
    public static class KeyHelper
    {
        private static readonly string[] itemsToRemove = { "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----" };

        public static string LoadFromFile(string path)
        {
            return RemoveHeaderFooterFromKey(System.IO.File.ReadAllText(path));
        }

        public static string RemoveHeaderFooterFromKey(string key)
        {
            string tmp = key;
            foreach(string item in itemsToRemove)
            {
                tmp = tmp.Replace(item, string.Empty);
            }
            return tmp.Trim();
        }
    }
}
