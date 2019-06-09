using System;
using System.Collections.Generic;
using System.Text;

namespace JwtManager
{
    public class JwtHeader
    {
        public string alg { get; set; }
        public string typ { get; set; }

        public void Set(Helpers.Algorithm algorithm, Helpers.KeySize size)
        {
            if(!Enum.IsDefined(typeof(Helpers.Algorithm), algorithm) || !Enum.IsDefined(typeof(Helpers.KeySize), size))
            {
                throw new Exception("Invalid values for algorithm or size.");
            }

            string algstr = "";

            switch(algorithm)
            {
                case Helpers.Algorithm.RSA:
                    algstr = "RS";
                    break;
                case Helpers.Algorithm.HMAC:
                    algstr = "HS";
                    break;
                case Helpers.Algorithm.ECDSA:
                    algstr = "ES";
                    break;
                case Helpers.Algorithm.RSASSA:
                    if(size == Helpers.KeySize.S512)
                    {
                        throw new Exception("Invalid size for algorithm.");
                    }
                    algstr = "PS";
                    break;
            }

            alg = algstr + ((int)size).ToString();
            typ = "JWT";
        }
    }
}
