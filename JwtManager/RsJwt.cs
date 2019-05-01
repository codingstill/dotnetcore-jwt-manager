using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;

namespace JwtManager
{
    public class RsJwt : Jwt
    {
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
        public Helpers.KeySize KeySize { get; set; }

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

            byte[] keyBytes = Convert.FromBase64String(PrivateKey);

            var privKeyObj = Asn1Object.FromByteArray(keyBytes);
            var privStruct = RsaPrivateKeyStructure.GetInstance((Asn1Sequence)privKeyObj);

            ISigner sig = SignerUtilities.GetSigner(SignerName);

            sig.Init(true, new RsaKeyParameters(true, privStruct.Modulus, privStruct.PrivateExponent));

            sig.BlockUpdate(bytesToSign, 0, bytesToSign.Length);
            byte[] signature = sig.GenerateSignature();

            segments.Add(Helpers.Base64Helper.UrlEncode(signature));
            return string.Join(".", segments.ToArray());
        }

        public override string Validate(string token)
        {
            string[] parts = token.Split('.');
            string header = parts[0];
            string payload = parts[1];
            string signature = parts[2];

            byte[] crypto = Helpers.Base64Helper.UrlDecode(parts[2]);

            string headerJson = Encoding.UTF8.GetString(Helpers.Base64Helper.UrlDecode(header));
            string payloadJson = Encoding.UTF8.GetString(Helpers.Base64Helper.UrlDecode(payload));

            byte[] keyBytes = Convert.FromBase64String(PublicKey);

            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            byte[] hash = ComputeHash(header, payload);

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm(AlgorithmName);
            byte[] tmp = Helpers.Base64Helper.UrlDecode(signature);
            if (!rsaDeformatter.VerifySignature(hash, tmp))
            {
                throw new Exception("Invalid signature");
            }

            return payloadJson;
        }

        private JwtHeader Header
        {
            get
            {
                JwtHeader header = new JwtHeader();
                header.Set(Helpers.Algorithm.RSA, KeySize);
                return Header;
            }
        }

        private string SignerName
        {
            get
            {
                return "SHA" + KeySize.ToString() + "withRSA";
            }
        }

        private string AlgorithmName
        {
            get
            {
                return "SHA" + KeySize.ToString();
            }
        }

        private byte[] ComputeHash(string header, string payload)
        {
            HashAlgorithm sha = HashAlgorithm.Create(AlgorithmName);

            if (sha == null) throw new Exception("Given key size is not valid.");

            return sha.ComputeHash(Encoding.UTF8.GetBytes(header + '.' + payload));
        }
    }
}
