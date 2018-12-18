using System;
using System.Collections.Generic;
using System.Text;

namespace JwtManager
{
    public abstract class Jwt
    {
        public string Algorithm { get; set; }
        public string Digest { get; set; }

        /// <summary>
        /// Creates and signs a Jwt token for the given payload with the given private key
        /// </summary>
        /// <param name="payload">A serialized JSON object to sign</param>
        /// <returns>A Jwt token signed with the given keys</returns>
        public abstract string Sign(string payload);

        /// <summary>
        /// Parses the input token and tries to validate the signature with the given public key
        /// </summary>
        /// <param name="token">A token to validate</param>
        /// <returns>The serialized payload if the token can be validated</returns>
        public abstract string Validate(string token);

        public static Jwt Create(string algorithm, int digest)
        {
            return new RsJwt();
        }
    }
}
