using System;
using System.Collections.Generic;
using System.Text;

namespace JwtManager
{
    public class JwtHeader
    {
        public string alg { get; set; }
        public string typ { get; set; }

        public void Set(Enums.Algorithm algorithm, Enums.KeySize size)
        {
            if(!Enum.IsDefined(typeof(Enums.Algorithm), algorithm) || !Enum.IsDefined(typeof(Enums.KeySize), size))
            {
                throw new Exception("Invalid values for algorithm or size.");
            }

            string algstr = "";

            switch(algorithm)
            {
                case Enums.Algorithm.RSA:
                    algstr = "RS";
                    break;
                case Enums.Algorithm.HMAC:
                    algstr = "HS";
                    break;
                case Enums.Algorithm.ECDSA:
                    algstr = "ES";
                    break;
                case Enums.Algorithm.RSASSA:
                    if(size == Enums.KeySize.S512)
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
