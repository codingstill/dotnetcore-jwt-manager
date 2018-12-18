#JWT RS256 C# library

A C# class that can sign and validate JWT tokens, wrapped in a simple library with a couple of helper functions.

To generate a compatible private key
```
openssl genrsa -out private.key 4096
```

To generate a compatible public key
```
openssl rsa -in private.key -outform PEM -pubout -out public.pem
```

## Sign a JWT token
```cs
using Newtonsoft.Json;

JwtManager.RsJwt jwt = new JwtManager.RsJwt
{
    PrivateKey = PrivateKey
};

string strToken = JsonConvert.SerializeObject(myToken);
string signedToken = jwt.Sign(strToken);
```
In case of an error, an Exception will be thrown.

## Validate a JWT token
```cs
using Newtonsoft.Json;

JwtManager.RsJwt jwt = new JwtManager.RsJwt
{
    PublicKey = PublicKey
};

string payload = jwt.Validate(strToken);
var myToken JsonConvert.DesrializeObject<JwtToken>(payload);
```

In case of an error, an Exception will be thrown.

The code has been tested both as a .NET and .NET Core library.

Check the Tests projects on more examples on how to use
