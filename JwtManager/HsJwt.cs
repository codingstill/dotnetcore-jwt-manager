using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace JwtManager
{
    public class HsJwt : Jwt
    {
        public Helpers.KeySize KeySize { get; set; }
        public string Secret { get; set; }

        public override string Sign(string payload)
        {
            List<string> segments = new List<string>();
            JwtHeader header = Header;

            DateTime issued = DateTime.Now;
            DateTime expire = DateTime.Now.AddHours(10);

            byte[] headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header, Formatting.None));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            segments.Add(Helpers.Base64Helper.UrlEncode(headerBytes));
            segments.Add(Helpers.Base64Helper.UrlEncode(payloadBytes));

            string stringToSign = string.Join(".", segments.ToArray());

            byte[] bytesToSign = Encoding.UTF8.GetBytes(stringToSign);

            byte[] secret = Encoding.UTF8.GetBytes(Secret);

            HMAC alg = GetHMAC(secret);
            byte[] hash = alg.ComputeHash(bytesToSign);

            segments.Add(Helpers.Base64Helper.UrlEncode(hash));

            return string.Join(".", segments.ToArray());
        }

        public override string Validate(string token)
        {
            string[] parts = token.Split('.');
            string header = parts[0];
            string payload = parts[1];
            string signature = parts[2];

            string headerJson = Encoding.UTF8.GetString(Helpers.Base64Helper.UrlDecode(header));
            string payloadJson = Encoding.UTF8.GetString(Helpers.Base64Helper.UrlDecode(payload));

            byte[] bytesToSign = Encoding.UTF8.GetBytes(string.Join(".", header, payload));

            byte[] secret = Encoding.UTF8.GetBytes(Secret);

            HMAC alg = GetHMAC(secret);
            byte[] hash = alg.ComputeHash(bytesToSign);

            string computedSignature = Helpers.Base64Helper.UrlEncode(hash);

            if(signature != computedSignature)
            {
                throw new Exception("Invalid signature.");
            }

            return payloadJson;
        }

        private JwtHeader Header
        {
            get
            {
                return new JwtHeader { alg = "HS" + ((int)KeySize).ToString(), typ = "JWT" };
            }
        }

        private HMAC GetHMAC(byte[] secret)
        {
            switch(KeySize)
            {
                case Helpers.KeySize.S256:
                    return new HMACSHA256(secret);
                case Helpers.KeySize.S384:
                    return new HMACSHA384(secret);
                case Helpers.KeySize.S512:
                    return new HMACSHA512(secret);
                default:
                    throw new Exception("Non-valid key size.");
            }
        }
    }
}
